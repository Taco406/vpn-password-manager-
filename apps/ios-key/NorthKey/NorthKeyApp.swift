// App entry. Registers for push (so unlock approvals can wake the app) and hosts the
// single content screen.

import SwiftUI
import UserNotifications

@main
struct NorthKeyApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.scenePhase) private var scenePhase
    /// Covers the UI whenever the app isn't frontmost. iOS snapshots the screen for the app
    /// switcher on the way out, and that snapshot is written to disk — without this the
    /// switcher (and anyone holding the unlocked phone) sees decrypted vault contents.
    @State private var shielded = false
    /// When the app left the foreground, for the auto-lock grace period below.
    @State private var backgroundedAt: Date?

    /// How long the vault may stay unlocked in the background. Short app-switches (copy a
    /// code, check a message) don't force a re-unlock; walking away does.
    private static let lockGrace: TimeInterval = 60

    var body: some Scene {
        WindowGroup {
            ContentView()
                .preferredColorScheme(.dark)
                .overlay {
                    if shielded { PrivacyShield() }
                }
        }
        // Single-parameter closure: the app targets iOS 16, where the two-parameter
        // onChange(of:initial:_:) doesn't exist yet.
        .onChange(of: scenePhase) { phase in
            // .inactive fires BEFORE the switcher snapshot is taken — cover it there, not in
            // .background, or the snapshot still captures the vault.
            shielded = phase != .active
            switch phase {
            case .background:
                backgroundedAt = Date()
            case .active:
                if let since = backgroundedAt, Date().timeIntervalSince(since) > Self.lockGrace {
                    NotificationCenter.default.post(name: .northKeyAutoLock, object: nil)
                }
                backgroundedAt = nil
            default:
                break
            }
        }
    }
}

extension Notification.Name {
    /// Posted when the app returns to the foreground after being away long enough that the
    /// vault should re-ask for the master password / Face ID.
    static let northKeyAutoLock = Notification.Name("northKeyAutoLock")
}

/// The opaque cover shown over the app in the switcher / while inactive.
private struct PrivacyShield: View {
    var body: some View {
        ZStack {
            Color(red: 0.04, green: 0.05, blue: 0.08).ignoresSafeArea()
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 44))
                .foregroundColor(.white.opacity(0.35))
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            if granted {
                DispatchQueue.main.async { application.registerForRemoteNotifications() }
            }
        }
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PushHandler.shared.register(token: deviceToken)
    }

    // An unlock-request push arrived — surface the approval sheet.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse) async {
        if let id = response.notification.request.content.userInfo["unlockRequestId"] as? String {
            await MainActor.run { PushHandler.shared.pendingUnlockRequestId = id }
        }
    }
}
