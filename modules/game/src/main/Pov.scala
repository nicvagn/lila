package lila.game

import chess.Color

import lila.core.game.*

object Pov:

  import lila.core.game.Pov.*

  def list(game: Game): List[Pov] = game.players.mapList(lila.core.game.Pov(game, _))

  def apply(game: Game, playerId: GamePlayerId): Option[Pov] =
    game.player(playerId).map { lila.core.game.Pov(game, _) }

  private inline def orInf(inline i: Option[Int]) = i.getOrElse(Int.MaxValue)
  private def isFresher(a: Pov, b: Pov)           = a.game.movedAt.isAfter(b.game.movedAt)

  def priority(a: Pov, b: Pov) =
    if !a.isMyTurn && !b.isMyTurn then isFresher(a, b)
    else if !a.isMyTurn && b.isMyTurn then false
    else if a.isMyTurn && !b.isMyTurn then true
    // first move has priority over games with more than 30s left
    else if orInf(a.remainingSeconds) < 30 && orInf(b.remainingSeconds) > 30 then true
    else if orInf(b.remainingSeconds) < 30 && orInf(a.remainingSeconds) > 30 then false
    else if !a.hasMoved && b.hasMoved then true
    else if !b.hasMoved && a.hasMoved then false
    else orInf(a.remainingSeconds) < orInf(b.remainingSeconds)

case class LightPov(game: LightGame, color: Color):
  export game.{ id as gameId }
  def player   = game.player(color)
  def opponent = game.player(!color)

object LightPov:

  def apply(game: LightGame, player: LightPlayer): LightPov = LightPov(game, player.color)

  def apply(game: LightGame, userId: UserId): Option[LightPov] =
    game.playerByUserId(userId).map { apply(game, _) }
