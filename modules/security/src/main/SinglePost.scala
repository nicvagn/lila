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
    if token.isEmpty then result("missing".some)
    else
      token.split('|') match
        case Array(rnd, sign) =>
          if !digestOf(rnd).hash_=(sign) then result("badSign".some)
          else if !tokens.get(rnd) then result("expired".some)
          else
            tokens.remove(rnd)
            result(none)
        case _ => result("weird".some)

  private def result(err: Option[String])(using req: RequestHeader) =
    val cold = !lila.common.Uptime.startedSinceMinutes(5)
    val endpoint = HTTPRequest.actionName(req)
    lila.mon.security.singlePost.consume(endpoint, err | "success").increment()
    err
      .filterNot(_ == "expired" && cold)
      .foreach: e =>
        logger
          .branch("singlePost")
          .info(s"$endpoint $e ${HTTPRequest.printReq(req)} ${HTTPRequest.printClient(req)}")
    err.isEmpty || cold

  private def digestOf(rnd: String)(using req: RequestHeader) =
    signer.sha1(s"$rnd|${enforceIp.get().so(HTTPRequest.ipAddressStr(req))}|${HTTPRequest.userAgent(req)}")

  def formMapping(using RequestHeader): Mapping[String] =
    optional(nonEmptyText)
      .transform(~_, _.some)
      .verifying("Session has expired, please try again", consumeToken)

  def formPair(using RequestHeader): (String, Mapping[String]) = "singlePost" -> formMapping

  def formPairWithLichobileCompat(using req: RequestHeader): (String, Mapping[String]) =
    if HTTPRequest.isLichobile(req)
    then "singlePost" -> optional(text).transform(~_, _.some)
    else formPair

  def signCheckForm = play.api.data.Form(
    single(
      "singlePost" ->
        optional(nonEmptyText)
          .transform(~_, _.some)
          .verifying("Session has expired, please try again", checkTokenSign)
    )
  )
