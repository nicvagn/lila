import { h, type VNode } from 'snabbdom';
import { fixCrazySan, plyToTurn } from 'lib/game/chess';
import { defined } from 'lib';
import { view as cevalView, renderEval as normalizeEval } from 'lib/ceval/ceval';

export interface Ctx {
  withDots?: boolean;
  showEval: boolean;
  showGlyphs?: boolean;
}

export const renderGlyph = (glyph: Tree.Glyph): VNode =>
  h(
    'glyph',
    { attrs: { title: glyph.name, 'aria-label': glyph.name, 'aria-assertive': 'polite' } },
    glyph.symbol,
  );

const renderEval = (e: string): VNode => h('eval', e.replace('-', '−'));

export const renderIndexText = (ply: Ply, withDots?: boolean): string =>
  plyToTurn(ply) + (withDots ? (ply % 2 === 1 ? '.' : '...') : '');

export const renderIndex = (ply: Ply, withDots?: boolean): VNode =>
  h(`index.sbhint${ply}`, renderIndexText(ply, withDots));

export function renderMove(ctx: Ctx, node: Tree.Node): VNode[] {
  const ev = cevalView.getBestEval({ client: node.ceval, server: node.eval });
  const nodes = [
    h(
      'san',
      { attrs: { 'aria-live': 'polite', 'aria-label': 'standard algebraic notation' } },
      fixCrazySan(node.san!),
    ),
  ];
  if (node.glyphs && ctx.showGlyphs) node.glyphs.forEach(g => nodes.push(renderGlyph(g)));
  if (node.shapes?.length) nodes.push(h('shapes'));
  if (ev && ctx.showEval) {
    if (defined(ev.cp)) nodes.push(renderEval(normalizeEval(ev.cp)));
    else if (defined(ev.mate)) nodes.push(renderEval('#' + ev.mate));
  }
  return nodes;
}

export const renderIndexAndMove = (ctx: Ctx, node: Tree.Node): VNode[] | undefined =>
  node.san ? [renderIndex(node.ply, ctx.withDots), ...renderMove(ctx, node)] : undefined;
