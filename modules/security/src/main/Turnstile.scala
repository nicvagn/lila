package lila.security

import play.api.ConfigLoader
import play.api.data.Forms.*
import play.api.data.{ Form, FormBinding }
import play.api.libs.json.*
import play.api.libs.ws.DefaultBodyWritables.*
import play.api.libs.ws.JsonBodyReadables.*
import play.api.libs.ws.StandaloneWSClient
import play.api.mvc.RequestHeader

import lila.common.HTTPRequest
import lila.common.autoconfig.*
import lila.common.config.given
import lila.core.config.*
import lila.core.security.{ TurnstileForm, TurnstilePublicConfig }

trait Turnstile extends lila.core.security.Turnstile:

  def verify(response: String)(using req: RequestHeader): Fu[Turnstile.Result]

  def verify()(using play.api.mvc.Request[?], FormBinding): Fu[Boolean] =
    verify(~Turnstile.form.bindFromRequest().value.flatten).dmap(_.ok)

object Turnstile:

  enum Result(val ok: Boolean):
    case Valid extends Result(true)
    case Disabled extends Result(true)
    case Fail extends Result(false)

  val field = "cf-turnstile-response" -> optional(nonEmptyText)
  val form = Form(single(field))

  private[security] case class Config(
      @ConfigName("site_key") siteKey: String,
      @ConfigName("secret_key") secretKey: Secret,
      enabled: Boolean
  ):
    def public = TurnstilePublicConfig(siteKey, enabled)
  private[security] given ConfigLoader[Config] = AutoConfig.loader[Config]

final class TurnstileSkip(config: TurnstilePublicConfig) extends Turnstile:

  def form[A](form: Form[A])(using req: RequestHeader) = TurnstileForm(form, config)

  def verify(response: String)(using req: RequestHeader) = fuccess(Turnstile.Result.Disabled)

final class TurnstileReal(
    ws: StandaloneWSClient,
    netDomain: NetDomain,
    config: Turnstile.Config
)(using Executor)
    extends Turnstile:

  import Turnstile.Result

  private case class GoodResponse(success: Boolean, hostname: String)
  private given Reads[GoodResponse] = Json.reads[GoodResponse]

  private case class BadResponse(`error-codes`: List[String]):
    def missingInput = `error-codes` contains "missing-input-response"
    override def toString = `error-codes`.mkString(",")
  private given Reads[BadResponse] = Json.reads[BadResponse]

  def form[A](form: Form[A])(using req: RequestHeader): TurnstileForm[A] =
    lila.mon.security.turnstile.form(HTTPRequest.clientName(req)).increment()
    TurnstileForm(form, config.public)

  def verify(response: String)(using req: RequestHeader): Fu[Result] =
    val client = HTTPRequest.clientName(req)
    given Conversion[Result, Fu[Result]] = fuccess
    def missingResponse: Result =
      logger.info(s"turnstile missing ${HTTPRequest.printClient(req)}")
      lila.mon.security.turnstile.hit(client, "missing").increment()
      Result.Fail
    if response.isEmpty then missingResponse
    else
      ws.url("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .post(
          Map(
            "secret" -> config.secretKey.value,
            "response" -> response,
            "remoteip" -> HTTPRequest.ipAddress(req).value,
            "sitekey" -> config.siteKey
          )
        )
        .flatMap:
          case res if res.status == 200 =>
            res.body[JsValue].validate[GoodResponse] match
              case JsSuccess(res, _) =>
                lila.mon.security.turnstile.hit(client, "success").increment()
                if res.success && res.hostname == netDomain.value then Result.Valid
                else Result.Fail
              case JsError(err) =>
                res.body[JsValue].validate[BadResponse].asOpt match
                  case Some(err) if err.missingInput =>
                    missingResponse
                  case Some(err) =>
                    lila.mon.security.turnstile.hit(client, err.toString).increment()
                    Result.Fail
                  case _ =>
                    lila.mon.security.turnstile.hit(client, "error").increment()
                    logger.info(s"turnstile $err ${res.body}")
                    Result.Fail
          case res =>
            lila.mon.security.turnstile.hit(client, res.status.toString).increment()
            logger.info(s"turnstile ${res.status} ${res.body}")
            Result.Fail
