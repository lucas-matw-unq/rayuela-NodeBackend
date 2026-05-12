# Check-in UI Dissected

This section provides a deep-dive into the actual Check-in screen. Every visible element maps to a specific architectural concept — a Riverpod provider, a navigation parameter, a platform plugin, or local widget state.

<style>
.ci-container { display: flex; gap: 2rem; flex-wrap: wrap; align-items: flex-start; margin: 1.5rem 0; }
.phone-mockup {
  flex-shrink: 0;
  width: 280px;
  background: #f0f2f0;
  border-radius: 36px;
  border: 8px solid #222;
  box-shadow: 0 20px 60px rgba(0,0,0,0.35), inset 0 0 0 2px #444;
  padding: 16px 12px 20px;
  position: relative;
  font-family: 'Segoe UI', sans-serif;
  color: #333;
}
.notch { width: 60px; height: 8px; background: #222; border-radius: 4px; margin: 0 auto 12px; }
.phone-header { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; position: relative; }
.phone-section { margin-bottom: 12px; position: relative; }
.phone-label { font-size: 9px; font-weight: 700; color: #666; letter-spacing: 0.8px; margin-bottom: 6px; text-transform: uppercase; }
.chip-row { display: flex; gap: 6px; }
.chip { padding: 6px 12px; border: 1.5px solid #ddd; border-radius: 20px; font-size: 11px; color: #888; background: #fff; }
.chip.active { border-color: #4DBA87; color: #4DBA87; font-weight: 600; }
.photo-placeholder { background: #e8ede9; border-radius: 8px; padding: 14px; text-align: center; font-size: 10px; color: #888; border: 1.5px dashed #b0c4b5; margin-bottom: 6px; }
.phone-button-row { display: flex; gap: 6px; }
.phone-button { flex: 1; padding: 8px; border: 1.5px solid #4DBA87; border-radius: 8px; background: #fff; font-size: 10px; color: #4DBA87; font-weight: 600; }
.location-box { background: #fff; border: 1px solid #dde8de; border-radius: 8px; padding: 8px 10px; display: flex; align-items: center; justify-content: space-between; }
.notes-box { background: #fff; border: 1px solid #dde8de; border-radius: 8px; padding: 8px 10px; min-height: 52px; }
.submit-btn { width: 100%; padding: 12px; background: #c8d8cb; border: none; border-radius: 10px; font-size: 12px; font-weight: 700; color: #7a9a7e; }
.home-indicator { width: 50px; height: 4px; background: #333; border-radius: 2px; margin: 14px auto 0; }
.ci-badge {
  display: inline-flex; align-items: center; justify-content: center;
  width: 20px; height: 20px; border-radius: 50%;
  background: #374151; color: #fff;
  font-size: 11px; font-weight: 700;
  flex-shrink: 0;
}
.ci-badge-lg { width: 28px; height: 28px; font-size: 13px; }
.legend { flex: 1; min-width: 280px; }
.ci-annotation {
  display: flex; gap: 0.9rem; align-items: flex-start;
  background: #fff; border: 1px solid #e5e7eb;
  border-left: 4px solid #d1d5db;
  border-radius: 8px; padding: 0.8rem 1rem;
  margin-bottom: 0.8rem;
  color: #374151;
}
.ci-ann-title { font-weight: 700; font-size: 0.88rem; margin-bottom: 0.25rem; }
.ci-ann-source { margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
.ci-ann-desc { font-size: 0.82rem; color: #4b5563; line-height: 1.55; }
.ci-pre {
  background: #1e2433; color: #c9d1d9;
  border-radius: 6px; padding: 0.6rem 0.9rem;
  font-family: monospace; font-size: 0.78rem; line-height: 1.6;
  overflow-x: auto; margin-top: 0.5rem;
}
</style>

<div class="ci-container">

<div class="phone-mockup">
<div class="notch"></div>
<div class="phone-header">
<span style="font-size:18px;">←</span>
<span style="font-size:13px;font-weight:700;">Eco Survey Project</span>
<span class="ci-badge" style="position:absolute;right:-8px;top:-4px;">1</span>
</div>
<div class="phone-section">
<div class="phone-label">What kind of check-in?</div>
<div class="chip-row">
<div class="chip active">Observation</div>
<div class="chip">Measurement</div>
</div>
<span class="ci-badge" style="position:absolute;right:-8px;top:0;">2</span>
</div>
<div class="phone-section">
<div class="phone-label">Photos · 0/3</div>
<div class="photo-placeholder">Add up to 3 photos to support your observation.</div>
<div class="phone-button-row">
<div class="phone-button" style="text-align:center;">📷 Camera</div>
<div class="phone-button" style="text-align:center;">🖼 Gallery</div>
</div>
<span class="ci-badge" style="position:absolute;right:-8px;top:0;">3</span>
</div>
<div class="phone-section">
<div class="phone-label">Location</div>
<div class="location-box">
<div style="display:flex;gap:6px;align-items:center;">
<span style="color:#4DBA87;">📍</span>
<div>
<div style="font-size:10px;font-weight:700;">37.42200, -122.08400</div>
<div style="font-size:9px;color:#888;">Accuracy ±5 m</div>
</div>
</div>
<div style="display:flex;gap:8px;color:#4DBA87;font-size:14px;">🗺 ↺</div>
</div>
<span class="ci-badge" style="position:absolute;right:-8px;top:0;">4</span>
</div>
<div class="phone-section">
<div class="phone-label">Notes (Optional)</div>
<div class="notes-box">
<div style="font-size:10px;color:#bbb;">Anything the project team should know?</div>
</div>
<span class="ci-badge" style="position:absolute;right:-8px;top:0;">5</span>
</div>
<div class="phone-section">
<button class="submit-btn" style="border:none;">Submit check-in</button>
<span class="ci-badge" style="position:absolute;right:-8px;top:4px;">6</span>
</div>
<div class="home-indicator"></div>
</div>

<div class="legend">
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">1</span>
<div>
<div class="ci-ann-title">App Bar title — "Eco Survey Project"</div>
<div class="ci-ann-source">`GoRouter` query parameters</div>
<div class="ci-ann-desc">Passed via `context.pushNamed` when navigating from the dashboard.</div>
</div>
</div>
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">2</span>
<div>
<div class="ci-ann-title">Task type chips</div>
<div class="ci-ann-source">`GoRouter` extra data</div>
<div class="ci-ann-desc">The list of available tasks is passed as `extra` from the project detail.</div>
</div>
</div>
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">3</span>
<div>
<div class="ci-ann-title">Photo picker</div>
<div class="ci-ann-source">`image_picker` plugin + local state</div>
<div class="ci-ann-desc">Images are picked via platform channels and stored in the widget's local `List<XFile>`.</div>
</div>
</div>
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">4</span>
<div>
<div class="ci-ann-title">GPS Coordinates</div>
<div class="ci-ann-source">`geolocator` plugin</div>
<div class="ci-ann-desc">Fetched fresh on screen load via platform channels.</div>
</div>
</div>
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">5</span>
<div>
<div class="ci-ann-title">Notes textarea</div>
<div class="ci-ann-source">`TextEditingController`</div>
<div class="ci-ann-desc">Standard ephemeral UI state.</div>
</div>
</div>
<div class="ci-annotation">
<span class="ci-badge ci-badge-lg">6</span>
<div>
<div class="ci-ann-title">Submit Button</div>
<div class="ci-ann-source">`CheckinController` (Riverpod)</div>
<div class="ci-ann-desc">Disabled while submitting or if required fields are missing.</div>
</div>
</div>
</div>
</div>

## Submit Flow Deep-Dive

What happens when the user taps **Submit check-in**:

```mermaid
sequenceDiagram
    participant UI as Screen (UI)
    participant Ctrl as CheckinController (Riverpod)
    participant Repo as CheckinsRepository
    participant API as Backend (NestJS)
    
    UI->>UI: Validate local state (images, task)
    UI->>Ctrl: submit(CheckinRequest)
    Ctrl->>Ctrl: state = AsyncLoading
    Ctrl->>Repo: submit(request)
    Repo->>Repo: Build FormData (Multipart)
    Repo->>API: POST /checkin
    API-->>Repo: 201 Created (CheckinResult)
    Repo-->>Ctrl: Success(result)
    Ctrl-->>UI: state = AsyncData(result)
    UI->>UI: Navigate to Success Screen
    UI->>UI: Refresh Global Auth State (Points)
```

## State Distribution

| element | state type | location |
| :--- | :--- | :--- |
| Selected chip | Local | `setState()` in Widget |
| Photo paths | Local | `List<XFile>` in Widget |
| GPS position | Local | `Position` in Widget |
| Submitting flag | Riverpod | `CheckinController` |
| Points earned | Riverpod | `authControllerProvider` |
