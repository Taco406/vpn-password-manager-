// The single screen: pairing state, live unlock-approval card, and the pocket TOTP
// viewer. Matches the desktop's dark aesthetic (#0A0E14 base, electric-cyan accent).

import SwiftUI

struct ContentView: View {
    @StateObject private var model = AppModel()

    var body: some View {
        ZStack {
            Color(hex: 0x0A0E14).ignoresSafeArea()
            VStack(spacing: 24) {
                header
                if let banner = model.banner {
                    Text(banner)
                        .font(.caption)
                        .foregroundColor(Color(hex: 0xF87171))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                switch model.state {
                case .needsServer:
                    ServerSetupView(model: model)
                case .unpaired:
                    PairingCeremonyView(model: model)
                case .paired:
                    pairedContent
                }
                Spacer()
            }
            .padding(20)

            if let request = model.pendingUnlock {
                UnlockApprovalView(request: request, model: model)
                    .transition(.move(edge: .bottom))
            }
        }
        .accentColor(Color(hex: 0x22D3EE))
    }

    private var header: some View {
        HStack {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundColor(Color(hex: 0x22D3EE))
            Text("NorthKey").font(.headline.bold())
            Spacer()
            Circle().fill(model.state == .paired ? Color(hex: 0x2ED47A) : Color.gray)
                .frame(width: 8, height: 8)
        }
        .padding(.top, 8)
    }

    private var pairedContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            Card {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Paired with Mac").font(.subheadline.bold())
                    Text("Approvals will appear here after Face ID.")
                        .font(.caption).foregroundColor(.gray)
                }
            }
            TotpViewerView(model: model)
        }
    }
}

// A rounded surface matching the desktop cards.
struct Card<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color(hex: 0x0F141C))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(hex: 0x1C2531)))
            .cornerRadius(16)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xff) / 255,
                  green: Double((hex >> 8) & 0xff) / 255,
                  blue: Double(hex & 0xff) / 255)
    }
}
