// The phone's Netdata aggregation math must match the desktop's Rust source of truth
// (crates/core/src/cloud/netdata.rs). These literal-fixture tests mirror the Rust unit tests:
// a drift here means the phone would show wrong numbers on the Servers dashboard.
//
// Reminder on indexing: Netdata's `/api/v1/data` returns labels[0] == "time" and each row is
// [ts, v0, v1, …], so a label at index i pairs with the row value at index i.

import XCTest
@testable import NorthKey

final class NetdataMathTests: XCTestCase {
    private func data(_ labels: [String], _ rows: [[Double]]) -> NetdataData {
        NetdataData(labels: labels, rows: rows)
    }

    func testLatestPicksMaxTimestamp() {
        // Out-of-order rows: the newest (ts 200) must win regardless of array order.
        let d = data(["time", "user"], [[200, 9], [100, 1], [150, 5]])
        XCTAssertEqual(d.latest?[1], 9)
    }

    func testCpuTotalSumsDimsAndClamps() {
        let d = data(["time", "user", "system", "steal"], [[100, 40, 25, 10]])
        XCTAssertEqual(NetdataMath.cpuTotal(d), 75, accuracy: 0.001)
        // Over 100 clamps to 100.
        let hot = data(["time", "user", "system"], [[100, 80, 40]])
        XCTAssertEqual(NetdataMath.cpuTotal(hot), 100, accuracy: 0.001)
    }

    func testRamUsedOverTotal() {
        let d = data(["time", "free", "used", "cached"], [[100, 100, 300, 100]])
        // used / (free+used+cached) = 300 / 500 = 60%.
        XCTAssertEqual(NetdataMath.ramUsed(d)!, 60, accuracy: 0.001)
    }

    func testSwapUsedOverFreePlusUsed() {
        let d = data(["time", "free", "used"], [[100, 300, 100]])
        // used / (free+used) = 100 / 400 = 25%.
        XCTAssertEqual(NetdataMath.swapUsed(d)!, 25, accuracy: 0.001)
        // No swap (all zero) -> nil, not a divide-by-zero.
        XCTAssertNil(NetdataMath.swapUsed(data(["time", "free", "used"], [[100, 0, 0]])))
    }

    func testDiskUsedExcludesRootReserve() {
        let d = data(["time", "avail", "used", "reserved for root"], [[100, 70, 30, 5]])
        // used / (avail+used) = 30 / 100 = 30% (reserve excluded).
        XCTAssertEqual(NetdataMath.diskUsed(d)!, 30, accuracy: 0.001)
    }

    func testLoadReturnsThree() {
        let d = data(["time", "load1", "load5", "load15"], [[100, 1.5, 0.9, 0.4]])
        let l = NetdataMath.load(d)
        XCTAssertEqual(l.0!, 1.5, accuracy: 0.001)
        XCTAssertEqual(l.1!, 0.9, accuracy: 0.001)
        XCTAssertEqual(l.2!, 0.4, accuracy: 0.001)
    }

    func testNamedLatestForStealProcsUptimePsi() {
        XCTAssertEqual(NetdataMath.namedLatest(data(["time", "steal"], [[100, 3.2]]), "steal", clamp: true)!, 3.2, accuracy: 0.001)
        XCTAssertEqual(NetdataMath.namedLatest(data(["time", "running"], [[100, 2]]), "running")!, 2, accuracy: 0.001)
        XCTAssertEqual(NetdataMath.namedLatest(data(["time", "uptime"], [[100, 90000]]), "uptime")!, 90000, accuracy: 0.001)
        // PSI reads the "some 60" window.
        XCTAssertEqual(NetdataMath.namedLatest(data(["time", "some 10", "some 60"], [[100, 5, 12]]), "some 60", clamp: true)!, 12, accuracy: 0.001)
        // Absent dim -> nil.
        XCTAssertNil(NetdataMath.namedLatest(data(["time", "user"], [[100, 1]]), "steal"))
    }

    func testSeriesSplitsDimAndTakesAbs() {
        let d = data(["time", "InOctets", "OutOctets"], [[200, 500, -300], [100, 100, -50]])
        let inSeries = NetdataMath.series(d, "InOctets", abs: true)
        // Ascending by time; |values|.
        XCTAssertEqual(inSeries.map { $0.0 }, [100, 200])
        XCTAssertEqual(inSeries.map { $0.1 }, [100, 500])
        let outSeries = NetdataMath.series(d, "OutOctets", abs: true)
        XCTAssertEqual(outSeries.map { $0.1 }, [50, 300])
    }
}
