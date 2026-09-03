/**
 * The tariff, in one place.
 *
 * This existed twice and the copies disagreed: the page offered a basket of
 * three portraits at the price of one, while the gatekeeper demanded three.
 * A customer following the page would have underpaid and been refused, and
 * the money would have sat in a component that cannot refund it.
 *
 * So there is one implementation, and `tests/test_pricing.js` runs it against
 * the gatekeeper's own `price_of` for every SKU shape. Two programs may still
 * hold the tariff, but they can no longer hold different ones quietly.
 */
export function priceOf(sku, config) {
  if (sku === "all") return config.pricePerDay * 30;
  if (sku.startsWith("m")) return config.pricePerTitle * new Set(sku.slice(1)).size;
  return config.pricePerTitle;
}
