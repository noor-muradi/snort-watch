function englishNameExpression() {
  return [
    "coalesce",
    ["get", "name_en"],
    ["get", "name:en"],
  ];
}

function preferEnglishNames(expression) {
  if (!Array.isArray(expression)) return expression;
  if (
    expression[0] === "case" &&
    hasNonLatinNameCondition(expression[1])
  ) {
    return englishNameExpression();
  }
  if (
    expression[0] === "get" &&
    ["name", "name_en", "name:en", "name:latin", "name:nonlatin"].includes(expression[1])
  ) {
    return englishNameExpression();
  }
  return expression.map(preferEnglishNames);
}

function hasNonLatinNameCondition(expression) {
  if (!Array.isArray(expression)) return false;
  if (expression[0] === "has" && expression[1] === "name:nonlatin") {
    return true;
  }
  return expression.some(hasNonLatinNameCondition);
}

export function preferEnglishMapLabels(style) {
  return {
    ...style,
    layers: style.layers.map((layer) => {
      if (layer.type !== "symbol" || !layer.layout?.["text-field"]) {
        return layer;
      }
      return {
        ...layer,
        layout: {
          ...layer.layout,
          "text-field": preferEnglishNames(layer.layout["text-field"]),
        },
      };
    }),
  };
}
