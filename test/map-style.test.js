import assert from "node:assert/strict";
import test from "node:test";
import { preferEnglishMapLabels } from "../src/map-style.js";

test("uses English-only names in symbol labels", () => {
  const style = {
    layers: [
      {
        id: "city",
        type: "symbol",
        layout: {
          "text-field": ["format", ["get", "name"], { "font-scale": 1.1 }],
        },
      },
      {
        id: "country",
        type: "symbol",
        layout: { "text-field": ["get", "name:nonlatin"] },
      },
      {
        id: "water",
        type: "symbol",
        layout: {
          "text-field": [
            "case",
            ["has", "name:nonlatin"],
            ["concat", ["get", "name:latin"], " ", ["get", "name:nonlatin"]],
            ["get", "name"],
          ],
        },
      },
      {
        id: "shield",
        type: "symbol",
        layout: { "text-field": ["get", "ref"] },
      },
      { id: "land", type: "fill", paint: { "fill-color": "#fff" } },
    ],
  };

  const localized = preferEnglishMapLabels(style);
  const englishName = [
    "coalesce",
    ["get", "name_en"],
    ["get", "name:en"],
  ];
  assert.deepEqual(localized.layers[0].layout["text-field"], [
    "format",
    englishName,
    { "font-scale": 1.1 },
  ]);
  assert.deepEqual(localized.layers[1].layout["text-field"], englishName);
  assert.deepEqual(localized.layers[2].layout["text-field"], englishName);
  assert.deepEqual(localized.layers[3], style.layers[3]);
  assert.deepEqual(localized.layers[4], style.layers[4]);
  assert.deepEqual(style.layers[0].layout["text-field"], [
    "format",
    ["get", "name"],
    { "font-scale": 1.1 },
  ]);
});
