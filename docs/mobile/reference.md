# Reference & Statistics

Quick reference for the Rayuela Mobile project.

## 📊 Project Stats

*   **Codebase**: ~13,600 lines of Dart
*   **Features**: 5 core features
*   **Languages**: 3 (English, Spanish, Portuguese)
*   **Platforms**: iOS and Android
*   **Auth Methods**: 3 (Email, Google, Guest)

---

## 🛠️ Key Dependencies

| Package | Purpose | Web/Backend Equivalent |
| :--- | :--- | :--- |
| `flutter_riverpod` | State management + DI | NestJS IoC + Zustand/Redux |
| `go_router` | URL-based navigation | React Router / Express router |
| `dio` | HTTP client | Axios / node-fetch |
| `flutter_secure_storage` | Token storage | OS Keychain (No browser equivalent) |
| `google_sign_in` | OAuth via Google | passport-google-oauth20 |
| `geolocator` | GPS access | Browser Geolocation API |
| `image_picker` | Camera/Gallery access | Browser file input |
| `flutter_map` | Interactive Maps | Leaflet.js |

---

## 🔍 Key File Quick Reference

| Component | Path |
| :--- | :--- |
| **App Entry & Bootstrap** | `lib/main.dart` · `lib/app/bootstrap.dart` |
| **Auth State Machine** | `lib/features/auth/presentation/providers/auth_controller.dart` |
| **HTTP Client & Interceptors** | `lib/core/network/api_client.dart` |
| **Router & Redirects** | `lib/core/router/app_router.dart` |
| **Riverpod Core Providers** | `lib/shared/providers/core_providers.dart` |
| **Error Hierarchy** | `lib/core/network/app_exception.dart` |
| **Result<T> Wrapper** | `lib/core/utils/result.dart` |
| **Multipart Check-in Upload** | `lib/features/checkin/data/sources/checkins_remote_source.dart` |
