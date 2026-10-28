// The band above the prompt, shared by several mods: one row of buttons, and under it
// a list of info lines. Each mod's render hook gets the band drawn by the mods beneath
// it (`previous`); when that band follows this layout, its buttons and lines are taken
// over, so every button stays in one row however long a line gets. The same file ships
// in each mod that draws there (tasklist, bi-dash, workers, sysmon); keep the copies in step.

const MARK = 'mods-band'

type Node = unknown
// A drawn element as `next(e)` hands it back: its children sit beside its props.
type El = { type?: string; props?: { key?: unknown; children?: Node[] }; children?: Node[] }

const keyOf = (n: Node) => String((n as El | null)?.props?.key ?? '')
const childrenOf = (n: Node): Node[] => {
  const el = n as El | null
  const c = el?.children ?? el?.props?.children
  return Array.isArray(c) ? c : c == null ? [] : [c]
}

/** The buttons and lines of a band drawn in this layout; anything else is one button-row item. */
export function bandParts(previous: Node): { buttons: Node[]; lines: Node[] } {
  if (previous == null || previous === false) return { buttons: [], lines: [] }
  const el = previous as El
  if (el.type === 'Box' && keyOf(el).endsWith(MARK)) {
    const kids = childrenOf(el)
    const row = kids.find(k => keyOf(k).endsWith(`${MARK}-buttons`))
    const list = kids.find(k => keyOf(k).endsWith(`${MARK}-lines`))
    return { buttons: childrenOf(row), lines: childrenOf(list) }
  }
  return { buttons: [previous], lines: [] }
}

type BoxCtor = (props: Record<string, unknown>) => unknown

/** The band with this mod's buttons added to the row and its lines added to the list. */
export function band(Box: BoxCtor, previous: Node, buttons: Node[], lines: Node[]): unknown {
  const prior = bandParts(previous)
  const allLines = [...prior.lines, ...lines.filter(Boolean)]
  return Box({
    key: MARK,
    flexDirection: 'column',
    rowGap: 1,
    children: [
      Box({ key: `${MARK}-buttons`, flexDirection: 'row', flexWrap: 'wrap', alignItems: 'center', columnGap: 1, rowGap: 1, children: [...prior.buttons, ...buttons] }),
      ...(allLines.length ? [Box({ key: `${MARK}-lines`, flexDirection: 'column', children: allLines })] : []),
    ],
  })
}
