

// -- invalida patrones de tipo -- y ;
export function hasInjection(value) {
  if (!value) return false;
  const invalidPatterns = [";", "--"];
  return invalidPatterns.some((p) => value.includes(p));
}
