package lila.msg

import play.api.data.*
import play.api.data.Forms.*
import play.api.libs.json.*
import scalalib.Json.given
import scalalib.paginator.*

import lila.common.Json.given

final class MsgCompat(
    api: MsgApi,
    lightUserApi: lila.core.user.LightUserApi
)(using Executor):

  private val maxPerPage = MaxPerPage(25)

  def inbox(pageOpt: Option[Int])(using me: Me): Fu[JsObject] =
    val page = pageOpt.fold(1)(_.atLeast(1).atMost(2))
    api.myThreads.flatMap: allThreads =>
      val threads =
        allThreads.slice((page - 1) * maxPerPage.value, (page - 1) * maxPerPage.value + maxPerPage.value)
      lightUserApi
        .preloadMany(threads.map(_.other(me)))
        .inject(Json.toJsObject:
          Paginator
            .fromResults(
              currentPageResults = threads,
              nbResults = allThreads.size,
              currentPage = page,
              maxPerPage = maxPerPage
            )
            .mapResults: t =>
              val user = lightUserApi.syncFallback(t.other(me))
              Json.obj(
                "id" -> user.id,
                "author" -> user.titleName,
                "name" -> t.lastMsg.text,
                "updatedAt" -> t.lastMsg.date,
                "isUnread" -> t.lastMsg.unreadBy(me)
              ))

  def reply(userId: UserId)(using
      play.api.mvc.Request[?],
      FormBinding
  )(using me: Me): Either[Form[?], Funit] =
    Form(single("text" -> text(minLength = 3)))
      .bindFromRequest()
      .fold(
        err => Left(err),
        text => Right(api.post(me, userId, text).void)
      )
