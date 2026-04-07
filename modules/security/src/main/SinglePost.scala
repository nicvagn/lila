package lila
package security

import play.api.mvc.RequestHeader
import play.api.data.Forms.*
import scalalib.SecureRandom

import lila.core.config.Secret
import lila.core.security.{ SinglePostToken, SinglePostMakeToken }
import lila.common.HTTPRequest
import play.api.data.Mapping

final class SinglePost(secret: Secret, settingStore: lila.memo.SettingStore.Builder)(using Executor):

  private type Rnd = String
  private type Err = "missing" | "badSign" | "expired" | "weird"

  private val signer = com.roundeights.hasher.Algo.hmac(secret.value)

  private val tokens = scalalib.cache.ExpireSetMemo[String](10.minutes)

  val enforceIp = settingStore[Boolean](
    "singlePostEnforceIp",
    default = true,
    text = "Enforce single post IP".some
  )

  val newToken: SinglePostMakeToken = req ?=>
    val rnd = SecureRandom.nextString(16)
    tokens.put(rnd)
    lila.mon.security.singlePost.newToken(HTTPRequest.actionName(req)).increment()
    SinglePostToken(s"$rnd|${digestOf(rnd).hex}")

  def consumeToken(token: String)(using RequestHeader): Boolean =
    test(token) match
      case Left(err) => result(err.some)
      case Right(rnd) if result(none) =>
        tokens.remove(rnd)
        true
      case Right(_) => false

  def preCheckForm(using RequestHeader) = play.api.data.Form:
    single:
      "singlePost" -> tokenMapping.verifying("Invalid token", preCheck)

  private def test(token: String)(using RequestHeader): Either[Err, Rnd] =
    if token.isEmpty then Left("missing")
    else
      token.split('|') match
        case Array(rnd, sign) =>
          if !digestOf(rnd).hash_=(sign) then Left("badSign")
          else if !tokens.get(rnd) then Left("expired")
          else Right(rnd)
        case _ => Left("weird")

  private def cold = !lila.common.Uptime.startedSinceMinutes(5)

  private def result(err: Option[Err])(using req: RequestHeader) =
    val endpoint = HTTPRequest.actionName(req)
    lila.mon.security.singlePost.consume(endpoint, err | "success").increment()
    err match
      case None => true
      case Some("expired") if cold => true
      case Some(error) =>
        logger
          .branch("singlePost")
          .info(s"$endpoint $error ${HTTPRequest.printReq(req)} ${HTTPRequest.printClient(req)}")
        false

  private def digestOf(rnd: String)(using req: RequestHeader) =
    signer.sha1(s"$rnd|${enforceIp.get().so(HTTPRequest.ipAddressStr(req))}|${HTTPRequest.userAgent(req)}")

  private def tokenMapping = optional(nonEmptyText).transform(~_, _.some)

  def formMapping(using RequestHeader): Mapping[String] =
    tokenMapping.verifying("Session has expired, please try again", consumeToken)

  def formPair(using RequestHeader): (String, Mapping[String]) = "singlePost" -> formMapping

  def formPairWithLichobileCompat(using req: RequestHeader): (String, Mapping[String]) =
    if HTTPRequest.isLichobile(req)
    then "singlePost" -> tokenMapping
    else formPair

  // allows expired tokens, but not invalid ones
  private def preCheck(token: String)(using req: RequestHeader): Boolean =
    test(token) match
      case Right(_) => true
      case Left("expired") => true
      case Left(err) =>
        lila.mon.security.singlePost.preCheck(HTTPRequest.actionName(req), err).increment()
        false
