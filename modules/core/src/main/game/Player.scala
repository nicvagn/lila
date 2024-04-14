package lila.core
package game

import _root_.chess.{ ByColor, Color, Elo, PlayerName, Ply }
import lila.core.id.GamePlayerId
import lila.core.userId.{ UserId, UserIdOf }
import lila.core.rating.data.{ IntRating, IntRatingDiff, RatingProvisional }
import cats.kernel.Eq

case class Player(
    id: GamePlayerId,
    color: Color,
    aiLevel: Option[Int],
    isWinner: Option[Boolean] = None,
    isOfferingDraw: Boolean = false,
    proposeTakebackAt: Ply = Ply.initial, // ply when takeback was proposed
    userId: Option[UserId] = None,
    rating: Option[IntRating] = None,
    ratingDiff: Option[IntRatingDiff] = None,
    provisional: RatingProvisional = RatingProvisional.No,
    blurs: Blurs = Blurs(0L),
    berserk: Boolean = false,
    blindfold: Boolean = false,
    name: Option[PlayerName] = None
):

  def playerUser =
    userId.flatMap: uid =>
      rating.map { PlayerUser(uid, _, ratingDiff) }

  // TODO: almost same as playerUser
  def userInfos: Option[UserInfo] =
    (userId, rating).mapN: (id, ra) =>
      UserInfo(id, ra, provisional)

  def isAi = aiLevel.isDefined

  def isHuman = !isAi

  def hasUser = userId.isDefined

  def isUser[U: UserIdOf](u: U) = userId.has(u.id)

  def wins = isWinner | false

  def goBerserk = copy(berserk = true)

  def finish(winner: Boolean) = copy(isWinner = winner.option(true))

  def offerDraw = copy(isOfferingDraw = true)

  def removeDrawOffer = copy(isOfferingDraw = false)

  def proposeTakeback(ply: Ply) = copy(proposeTakebackAt = ply)

  def removeTakebackProposition = copy(proposeTakebackAt = Ply.initial)

  def isProposingTakeback = proposeTakebackAt > 0

  def before(other: Player) =
    ((rating, id), (other.rating, other.id)) match
      case ((Some(a), _), (Some(b), _)) if a != b => a.value > b.value
      case ((Some(_), _), (None, _))              => true
      case ((None, _), (Some(_), _))              => false
      case ((_, a), (_, b))                       => a.value < b.value

  def ratingAfter = rating.map(_.applyDiff(~ratingDiff))

  def stableRating = rating.ifFalse(provisional.value)

  def stableRatingAfter = stableRating.map(_.applyDiff(~ratingDiff))

  def light = LightPlayer(color, aiLevel, userId, rating, ratingDiff, provisional, berserk)

object Player:
  given Eq[Player] = Eq.by(p => (p.id, p.userId))