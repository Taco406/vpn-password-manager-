// Read-only pocket TOTP viewer. Entries are fetched per-open over the E2E channel and
// held only in memory — nothing at rest beyond the Secure-Enclave key.

import SwiftUI

struct TotpViewerView: View {
    @ObservedObject var model: AppModel
    @State private var now = Date()
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Codes").font(.subheadline.bold())
            if model.totpEntries.isEmpty {
                Card { Text("Open to fetch your codes.").font(.caption).foregroundColor(.gray) }
            } else {
                ForEach(model.totpEntries) { entry in
                    Card {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(entry.title).font(.subheadline)
                                Text(Rfc6238.code(secret: entry.secret, algo: entry.algo,
                                                  digits: entry.digits, period: entry.period, at: now))
                                    .font(.system(.title2, design: .monospaced).bold())
                                    .foregroundColor(Color(hex: 0x22D3EE))
                            }
                            Spacer()
                            Text("\(Rfc6238.remainingSeconds(period: entry.period, at: now))s")
                                .font(.caption.monospaced()).foregroundColor(.gray)
                        }
                    }
                }
            }
        }
        .onReceive(timer) { now = $0 }
    }
}
