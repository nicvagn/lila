import type { Run } from './interfaces';
import { opposite, uciToMove } from '@lichess-org/chessground/util';
import { makeFen } from 'chessops/fen';
import { chessgroundDests } from 'chessops/compat';

export const makeCgOpts = (run: Run, canMove: boolean, flipped: boolean): CgConfig => {
  const cur = run.current;
  const pos = cur.position();
  return {
    fen: makeFen(pos.toSetup()),
    orientation: flipped ? opposite(run.pov) : run.pov,
    turnColor: pos.turn,
    movable: {
      color: run.pov,
      dests: canMove ? chessgroundDests(pos) : undefined,
    },
    check: !!pos.isCheck(),
    lastMove: uciToMove(cur.lastMove()),
    animation: {
      enabled: cur.moveIndex >= 0,
    },
  };
};

export const povMessage = (run: Run): string =>
  run.pov === 'white'
    ? i18n.storm.youPlayTheWhitePiecesInAllPuzzles
    : i18n.storm.youPlayTheBlackPiecesInAllPuzzles;
