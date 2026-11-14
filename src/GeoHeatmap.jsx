import { useEffect, useRef, useState } from "react";
import "maplibre-gl/dist/maplibre-gl.css";
import mapWorkerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url";
import { preferEnglishMapLabels } from "./map-style.js";

const REFRESH_MS = 60_000;
const MAP_THEME_STORAGE_KEY = "snort-watch-map-theme";
const MAP_STYLE_URLS = {
  dark: "https://tiles.openfreemap.org/styles/dark",
  light: "https://tiles.openfreemap.org/styles/positron",
};

function geoJsonFor(data) {
  const maximum = data.locations.reduce(
    (largest, location) => Math.max(largest, location.count),
    0,
  );
  return {
    type: "FeatureCollection",
    features: data.locations.map(({ latitude, longitude, count }) => ({
      type: "Feature",
      geometry: { type: "Point", coordinates: [longitude, latitude] },
      properties: {
        count,
        weight: maximum ? Math.log1p(count) / Math.log1p(maximum) : 0,
      },
    })),
  };
}

function GeoHeatmap() {
  const [mapTheme, setMapTheme] = useState(() =>
    window.localStorage.getItem(MAP_THEME_STORAGE_KEY) === "light" ? "light" : "dark",
  );
  const [data, setData] = useState(null);
  const [dataError, setDataError] = useState("");
  const [mapError, setMapError] = useState("");
  const mapElement = useRef(null);
  const mapInstance = useRef(null);
  const latestData = useRef(null);
  latestData.current = data;

  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const response = await fetch("/api/geo/alerts");
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error ?? `Request failed (${response.status})`);
        }
        if (active) {
          setData(payload);
          setDataError("");
        }
      } catch (fetchError) {
        if (active) setDataError(fetchError.message);
      }
    }

    void refresh();
    const timer = window.setInterval(refresh, REFRESH_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let active = true;
    let map;
    let resizeObserver;
    const controller = new AbortController();

    async function initializeMap() {
      try {
        setMapError("");
        const [maplibre, styleResponse] = await Promise.all([
          import("maplibre-gl"),
          fetch(MAP_STYLE_URLS[mapTheme], { signal: controller.signal }),
        ]);
        if (!styleResponse.ok) {
          throw new Error(`Basemap style request failed (${styleResponse.status})`);
        }
        const style = preferEnglishMapLabels(await styleResponse.json());
        if (!active || !mapElement.current) return;

        maplibre.setWorkerUrl(mapWorkerUrl);
        map = new maplibre.Map({
          container: mapElement.current,
          style,
          center: [0, 20],
          zoom: 1.5,
          minZoom: 1,
        });
        map.addControl(new maplibre.NavigationControl(), "top-right");
        map.on("error", (event) => {
          const message = event.error?.message ?? "A map resource failed to load.";
          console.error(`MapLibre error: ${message}`);
          setMapError(message);
        });
        mapInstance.current = map;
        resizeObserver = new ResizeObserver(() => map.resize());
        resizeObserver.observe(mapElement.current);
        map.once("load", () => {
          if (!active) return;
          map.resize();
          map.addSource("alert-locations", {
            type: "geojson",
            data: geoJsonFor(latestData.current ?? { locations: [] }),
          });
          map.addLayer({
            id: "alert-location-heat",
            type: "heatmap",
            source: "alert-locations",
            paint: {
              "heatmap-weight": ["get", "weight"],
              "heatmap-intensity": ["interpolate", ["linear"], ["zoom"], 0, 1, 9, 3],
              "heatmap-radius": ["interpolate", ["linear"], ["zoom"], 0, 12, 9, 32],
              "heatmap-opacity": 0.78,
              "heatmap-color": [
                "interpolate",
                ["linear"],
                ["heatmap-density"],
                0, "rgba(45, 99, 155, 0)",
                0.2, "#315f9b",
                0.45, "#29a886",
                0.7, "#f2cd54",
                1, "#ed654a",
              ],
            },
          });
        });
      } catch (error) {
        if (active && error.name !== "AbortError") {
          setMapError(error.message);
        }
      }
    }

    void initializeMap();
    return () => {
      active = false;
      controller.abort();
      resizeObserver?.disconnect();
      map?.remove();
      mapInstance.current = null;
    };
  }, [mapTheme]);

  useEffect(() => {
    window.localStorage.setItem(MAP_THEME_STORAGE_KEY, mapTheme);
  }, [mapTheme]);

  useEffect(() => {
    const source = mapInstance.current?.getSource("alert-locations");
    if (source && data) source.setData(geoJsonFor(data));
  }, [data]);

  return (
    <section className="geo-panel" aria-labelledby="geo-heading">
      <div className="geo-heading">
        <div>
          <p className="eyebrow">ALERT ORIGINS</p>
          <h2 id="geo-heading">IP geolocation heatmap</h2>
          <p className="geo-copy">
            Public source and destination IPs, weighted by alerts across retained history.
          </p>
        </div>
        <div className="geo-heading-actions">
          <button
            className="map-theme-toggle"
            type="button"
            aria-label={`Switch to ${mapTheme === "dark" ? "light" : "dark"} map`}
            onClick={() => setMapTheme(mapTheme === "dark" ? "light" : "dark")}
          >
            <span aria-hidden="true">{mapTheme === "dark" ? "☀" : "☾"}</span>
            {mapTheme === "dark" ? "Light map" : "Dark map"}
          </button>
          {data && (
            <span className="geo-count">
              {data.locations.length.toLocaleString()} mapped locations
            </span>
          )}
        </div>
      </div>
      {dataError && (
        <div className="geo-empty" role="status">
          <strong>Geolocation unavailable</strong>
          <p>{dataError}</p>
          <small>Configure MaxMind GeoLite2 credentials in .env and restart the console.</small>
        </div>
      )}
      {mapError && (
        <div className="geo-empty" role="status">
          <strong>Map unavailable</strong>
          <p>{mapError}</p>
        </div>
      )}
      {!dataError && data && data.locations.length === 0 && (
        <div className="geo-empty">
          <strong>No public IP locations to show</strong>
          <p>Mapped alert locations will appear here when available.</p>
        </div>
      )}
      <div
        className={`geo-map ${mapTheme}`}
        ref={mapElement}
        role="img"
        aria-label="English-language map heatmap showing alert counts by public IP geolocation"
      />
      {data?.unmappedAddresses > 0 && (
        <p className="geo-note">
          {data.unmappedAddresses.toLocaleString()} public IPs were not found in the database.
        </p>
      )}
      <p className="geo-attribution">
        Map data &copy; OpenFreeMap, OpenMapTiles, and OpenStreetMap contributors. IP locations are approximate.
      </p>
    </section>
  );
}

export default GeoHeatmap;
