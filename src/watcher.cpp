#include <algorithm>
#include <codecvt>
#include <locale>
#include <filesystem>
#include <fstream>

#include "config.hpp"
#include "watcher.hpp"
#include "utils.hpp"
#include "logger.hpp"
#include "documents.hpp"
#include "aggregator.hpp"

// fs::file_size() calls GetFileAttributesEx internally, which OneDrive's
// kernel VFS filter (reparse tag 0x9000601a) satisfies from its metadata
// cache. That cache is not updated for excluded file types, so sizes appear
// frozen. Opening the file with a real handle forces OneDrive to report the
// actual on-disk size via GetFileSizeEx on the open handle.
static uint64_t getRealFileSize(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return 0;
    const std::streamoff pos = f.tellg();
    return pos < 0 ? 0 : static_cast<uint64_t>(pos);
}

Logwatch::LogWatcher Logwatch::watcher;

std::string Logwatch::LogWatcher::watchSnapshotPath(const std::string& ext) const {
    const auto root = fs::path(REL::Module::get().filename()).parent_path();
	const std::string fileName = "WatchSnapshot." + ext;
    return (root / "Data" / "SKSE" / "Plugins" / PRODUCT_NAME / "Watch" / fileName).string();
}

std::string Logwatch::LogWatcher::watchTimeStamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &time);
#else
    localtime_r(&t, &tm);
#endif

    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

void Logwatch::LogWatcher::getSortedSnapshot(std::vector<std::pair<std::string, Counts>>& sorted, const Snapshot& snap) const {
    sorted.reserve(snap.size());
    for (const auto& [modKey, s] : snap) {
        Counts c;
        c.errors = s.errors;
        c.warnings = s.warnings;
        c.fails = s.fails;
        c.others = s.others;
        sorted.emplace_back(modKey, c);
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) {
            return a.first < b.first;
        });
}

size_t Logwatch::LogWatcher::hashWatchSnapshot(const Snapshot& snap) const {
    std::vector<std::pair<std::string, Counts>> sortedSnap;
	getSortedSnapshot(sortedSnap, snap);

	// Same as FNV-1a, but we mix in counts for each mod.
    constexpr uint64_t FNV_OFFSET = 1469598103934665603ull;
    constexpr uint64_t FNV_PRIME = 1099511628211ull;

    uint64_t h = FNV_OFFSET;

    for (const auto& [mod, s] : snap) {

        uint64_t he = FNV_OFFSET;
        for (unsigned char c : mod) {
            he ^= c;
            he *= FNV_PRIME;
        }

#define mix(count) he ^= count; he *= FNV_PRIME;

        mix(s.errors);
        mix(s.warnings);
        mix(s.fails);
        mix(s.others);

        h ^= he;
        h *= FNV_PRIME;
    }

    return size_t(h);
}

inline void writeWatchToFile(std::ofstream& to, const std::string& ts, const std::vector<std::pair<std::string, Logwatch::Counts>>& sortedSnap) {
    to << "-----[ Watch Snapshot @ " << ts << " ]--------------\n";
    for (const auto& [mod, c] : sortedSnap) {
        to << mod
            << ", " << c.errors << " errors"
            << ", " << c.warnings << " warnings"
            << ", " << c.fails << " fails"
            << ", " << c.others << " others"
            << "\n";
    }
    to << "\n";
    to.flush();
}

void Logwatch::LogWatcher::saveWatchIfChanged(const Snapshot& snap) {
    if (!config.saveWatch) return;

    const size_t currentHash = hashWatchSnapshot(snap);
    if (currentHash == lastWatchHash) return;
    lastWatchHash = currentHash;
    logger::info("[Snapshot] hash changed, saving WatchSnapshot ({} mods tracked)", snap.size());

    const auto outPath = watchSnapshotPath("log");
    const auto csvPath = watchSnapshotPath("csv");
    fs::create_directories(fs::path(outPath).parent_path());

    std::vector<std::pair<std::string, Counts>> sortedSnap;
    getSortedSnapshot(sortedSnap, snap);

    const std::string ts = watchTimeStamp();

    try {
        std::ofstream out(outPath, std::ios::trunc);
        std::ofstream csv(csvPath, std::ios::trunc);
        if (!out) {
            logger::error("saveWatchIfChanged failed to open {}", outPath);
            return;
        }
        if (!csv) {
            logger::error("saveWatchIfChanged failed to open {}", csvPath);
            return;
        }

		writeWatchToFile(out, ts, sortedSnap);
		writeWatchToFile(csv, ts, sortedSnap);
    }
    catch (const std::exception& e) {
        logger::error("saveWatchIfChanged failed due to {}", e.what());
    }
}

void Logwatch::OnMatch(const Match& m) {
    if (m.file.find("Log Watcher") == std::string::npos) {
        SKSE::log::debug("File:{} Level:{} Line No.:{}", m.file, m.level, m.lineNo);
    }
    aggr.add(m);
}

Logwatch::LogType Logwatch::classify(const std::filesystem::path& p) {
    const std::string s = Utils::toUTF8(p);
    return (s.find("Logs\\Script") != std::string::npos || s.find("Logs/Script") != std::string::npos)
        ? LogType::Papyrus : LogType::Generic;
}

bool Logwatch::LogWatcher::shouldInclude(const fs::path& file) const {
    const auto s = Utils::toUTF8(file.filename());
    if (!std::regex_search(s, config.includeFileRegex)) return false;
    if (std::regex_search(s, config.excludeFileRegex)) return false;
    // Exclude LogWatcher's own output files to prevent a feedback loop where
    // the watcher reads its own snapshot, inflates aggregator counts, saves a
    // new snapshot, then reads that, etc.
    if (s.find("WatchSnapshot") != std::string::npos) return false;
    return true;
}

void Logwatch::LogWatcher::discoverFiles(std::vector<fs::path>& out, const fs::path& root, const std::stop_token& stop) {

    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) return;

    auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator end;

    if (ec) {
        const std::string rootToPrint = Utils::replaceUsername(Utils::toUTF8(root));
        logger::info("discoverFiles: cannot iterate over {}: {}", rootToPrint, ec.message());
        return;
    }

    while (it != end) {

        if (stop.stop_requested()) break;

        const auto& p = it->path();
        
        // collect files
        if (fs::is_regular_file(p, ec) && shouldInclude(p)) {
            out.push_back(p);
        }

        ec.clear();

        it.increment(ec); // increment iterator safely

        if (ec) {
            const std::string rootToPrint = Utils::replaceUsername(Utils::toUTF8(root));
            logger::info("discoverFiles: skipping path under {}: {}", rootToPrint, ec.message());
            ec.clear();
        }
    }
}

static const char* runStateStr(Logwatch::RunState rs) {
    switch (rs) {
        case Logwatch::RunState::Running:          return "Running";
        case Logwatch::RunState::AutoStopPending:  return "AutoStopPending";
        case Logwatch::RunState::Stopped:          return "Stopped";
        default:                                   return "Unknown";
    }
}

void Logwatch::LogWatcher::watcherLoop(const std::stop_token& stop) {

    uint64_t pollCount = 0;

    while (!stop.stop_requested()) {

        if (!isFirstPollDone()) {
            logger::info("Watcher initially starting or resumed");
        }

		// Handle paused state
        if (getRunState() == RunState::Stopped) {
            logger::info("Watcher paused; sleeping until resumed");
            std::unique_lock wake_lock(_wake_mutex_);
            _wake_cv_.wait(
                wake_lock,
                [&] {
                    return stop.stop_requested() || getRunState() != RunState::Stopped;
                }
            );
            logger::debug("[WatcherLoop] Woke from paused sleep | stop={} state={}",
                stop.stop_requested(), runStateStr(getRunState()));
            continue;
        }

        try {
            scanOnce(stop); // Unlocked scan (only critical parts have locks)
        } catch (const std::exception& e) {
            logger::error("[WatcherLoop] scanOnce threw: {}", e.what());
        } catch (...) {
            logger::error("[WatcherLoop] scanOnce threw unknown exception");
        }

        resetWarmingUp();

		markFirstPollDone();
        ++pollCount;

        // Periodic heartbeat so we can confirm the thread is alive in logs
        if (pollCount % 60 == 0) {
            struct FileDiag { std::string key; fs::path path; uint64_t offset; uint64_t sizeLastSeen; };
            std::vector<FileDiag> snapshot;
            {
                std::lock_guard lock(_mutex_);
                snapshot.reserve(files.size());
                for (const auto& [k, fi] : files) {
                    snapshot.push_back({ k, fi.path, fi.state.offset, fi.state.sizeLastSeen });
                }
            }

            size_t growing = 0, truncated = 0, unchanged = 0;
            for (const auto& fd : snapshot) {
                const uint64_t cur = getRealFileSize(fd.path);
                if      (cur > fd.offset) ++growing;
                else if (cur < fd.offset) ++truncated;
                else                      ++unchanged;
            }

            logger::info("[Heartbeat] poll={} files_tracked={} growing={} truncated={} unchanged={}",
                pollCount, snapshot.size(), growing, truncated, unchanged);

            // Dump Papyrus files and any "growing" files so we can see their state
            for (const auto& fd : snapshot) {
                const bool isPapyrus = fd.key.find("apyrus") != std::string::npos || fd.key.find("papyrus") != std::string::npos;
                const uint64_t cur = getRealFileSize(fd.path);
                const bool isGrowing = cur > fd.offset;
                if (isPapyrus || isGrowing) {
                    logger::info("[Heartbeat:File] offset={} sizeAtDisc={} curSize={} growing={} | {}",
                        fd.offset, fd.sizeLastSeen, cur, isGrowing ? "YES" : "no",
                        Utils::replaceUsername(fd.key));
                }
            }
        }

        // Schedule notifications / mails
        if (!stop.stop_requested()) {
            const auto snap = aggr.snapshot();
			saveWatchIfChanged(snap);
            mayNotifyPinnedAlerts(snap);
            mayNorifyPeriodicAlerts(snap);
        }

		// Handle auto-stop after first poll
        if (getRunState() == RunState::AutoStopPending) {
            logger::info("Watcher pausing after first poll");
			setRunState(RunState::Stopped);
            continue;
		}

        // get poll interval without keeping _mutex_ locked
        std::chrono::milliseconds sleep_for;
        {
            std::lock_guard lock(_mutex_);
            sleep_for = config.pollInterval;
        }

        // Stop-aware and paused-aware sleep
        std::unique_lock wake_lock(_wake_mutex_);
        const auto until = Clock::now() + sleep_for;
        const bool woke_by_signal = _wake_cv_.wait_until(wake_lock, until,
            [&] {
                return stop.stop_requested() || getRunState() == RunState::Stopped;
            }
        );

    }

    logger::info("Watcher thread exited");
}

void Logwatch::LogWatcher::scanOnce(const std::stop_token& stop) {

    std::vector<fs::path> discovered;
    discovered.reserve(64);
    for (const auto& r : roots) {
        if (stop.stop_requested()) return;
        discoverFiles(discovered, r, stop);
    }

    for (const auto& p : discovered) {
        if (stop.stop_requested()) return;

        std::error_code ec;
        const auto canonPath = fs::weakly_canonical(p, ec);
        const auto canon = Utils::toUTF8(canonPath);

		// critical section: check if we need to insert
        bool need_insert = false;
        bool start_from_end = false;
        {
            std::lock_guard lock(_mutex_);
            need_insert = (files.find(canon) == files.end());
            start_from_end = !config.deepScan;
        }

        if (!need_insert) continue;

		// Prepare FileInfo outside lock
        FileInfo fi;
        fi.path = p;
        fi.type = classify(fi.path);

        fi.state.writeTime = fs::last_write_time(p, ec);
        fi.state.lastPoll = Clock::now();

        const auto sz = getRealFileSize(p);
        fi.state.sizeLastSeen = sz;
        fi.state.offset = start_from_end ? fi.state.sizeLastSeen : 0;
        fi.state.lineNo = 0;

        logger::debug("[ScanOnce] New file: {} | size={} offset={} deepScan={}",
            Utils::replaceUsername(canon), fi.state.sizeLastSeen, fi.state.offset, !start_from_end);

		// critical section: insert file if still not present
        {
            std::lock_guard lock(_mutex_);
            if (files.find(canon) == files.end()) {
                files.emplace(canon, std::move(fi));
            }
        }
    }

    if (stop.stop_requested()) return;

    // Cache keys under lock
    std::vector<std::string> keys;
    {
        std::lock_guard lock(_mutex_);
        keys.reserve(files.size());
        for (auto& f : files) keys.push_back(f.first);
    }

    int tailCount = 0;

	// Work unlocked through the cached keys
    for (const auto& key : keys) {
        if (stop.stop_requested()) return;

		// get state snapshot under lock
        FileInfo snap;
        {
            std::lock_guard lock(_mutex_);
            auto it = files.find(key);
            if (it == files.end()) continue;
			snap = it->second;
        }

        // I/O phase (unlocked)
        std::error_code ec;
        const bool exists = fs::exists(snap.path, ec);
        const auto size = exists ? getRealFileSize(snap.path) : 0ull;
        const auto wt = exists ? fs::last_write_time(snap.path, ec) : decltype(snap.state.writeTime){};

        // Erase locked if the file vanished
        if (!exists) {
            logger::debug("[ScanOnce] File vanished, removing: {}", Utils::replaceUsername(key));
            std::lock_guard lock(_mutex_);
            auto it = files.find(key);
            if (it != files.end()) files.erase(it);
            continue;
        }

        // Handle truncation/rotation in the snapshot
        if (size < snap.state.offset) {
            logger::info("[ScanOnce] Truncated/rotated: {} | offset={} -> 0 (new size={})",
                Utils::toUTF8(snap.path.filename()), snap.state.offset, size);
            snap.state.offset = 0;
            snap.state.lineNo = 0;
        }

        // Tail if there is new data
        bool tailed = false;
        if (size > snap.state.offset) {
            const auto delta = size - snap.state.offset;
            logger::debug("[ScanOnce] Tailing: {} | offset={} size={} delta={}",
                Utils::replaceUsername(key), snap.state.offset, size, delta);
            const auto oldOffset = snap.state.offset;
            tailFile(snap, stop);
            logger::info("[Tail] {} | +{} bytes (offset {} -> {})",
                Utils::toUTF8(snap.path.filename()), snap.state.offset - oldOffset, oldOffset, snap.state.offset);
            tailed = true;
            ++tailCount;
        }

		// Commit updated state back under lock
        {
            std::lock_guard lock(_mutex_);
            auto fit = files.find(key);
            if (fit == files.end()) continue;

            auto& fi = fit->second;
            if (!fs::exists(fi.path, ec)) { files.erase(fit); continue; }

            fi.state.sizeLastSeen = size;
            fi.state.writeTime = wt;
            if (tailed) {
                fi.state.offset = snap.state.offset;
                fi.state.lineNo = snap.state.lineNo;
            }
        }
    }

}


void Logwatch::LogWatcher::tailFile(FileInfo& fi, const std::stop_token& stop) {
    const auto size = getRealFileSize(fi.path);
    if (size == 0 || size <= fi.state.offset) return;

    size_t chunkCap = KB2B(fi.type == LogType::Papyrus ? config.papyrusMaxChunkKB : config.maxChunkKB);

    if (config.autoBoostOnBacklog) {
        const uint64_t backlog = (size > fi.state.offset) ? (size - fi.state.offset) : 0;
        if (backlog > MB2B(config.backlogBoostThresholdMB)) {
            double boosted = double(chunkCap) * config.backlogBoostFactor;
            chunkCap = size_t(std::min<double>(boosted, double(MB2B(config.maxBoostCapMB))));
        }
    }

    const auto toRead = std::min<uint64_t>(chunkCap, size - fi.state.offset);

    logger::debug("[TailFile] {} | offset={} size={} toRead={} chunkCap={}",
        Utils::toUTF8(fi.path.filename()), fi.state.offset, size, toRead, chunkCap);

    if (stop.stop_requested()) return;

    std::ifstream in(fi.path, std::ios::binary);
    if (!in) {
        logger::debug("[TailFile] Failed to open file: {}", Utils::toUTF8(fi.path.filename()));
        return;
    }

    in.seekg(static_cast<std::streamoff>(fi.state.offset), std::ios::beg);

    std::string buf;
    buf.resize(toRead);
    in.read(&buf[0], static_cast<std::streamsize>(toRead));

    const auto offset = static_cast<size_t>(in.gcount());
    buf.resize(offset);
    fi.state.offset += offset;

    logger::debug("[TailFile] Read {} bytes; new offset={}", offset, fi.state.offset);

    parseBufferAndEmit(fi, std::move(buf), stop);
}

void Logwatch::LogWatcher::parseBufferAndEmit(FileInfo& fi, std::string&& chunk, const std::stop_token& stop) {

    const size_t lineCap = KB2B(fi.type == LogType::Papyrus ? config.papyrusMaxLineKB : config.maxLineKB);

    logger::debug("[ParseEmit] {} | chunk={} bytes lineCap={} bytes",
        Utils::toUTF8(fi.path.filename()), chunk.size(), lineCap);

    size_t start = 0;
    size_t linesProcessed = 0;
    size_t linesSkippedCap = 0;
    while (start < chunk.size() && !stop.stop_requested()) {
        size_t end = chunk.find_first_of("\r\n", start);
        if (end == std::string::npos) end = chunk.size();

        const size_t len = end - start;
        if (len <= lineCap) {
            // This must be string_view to avoid allocating new memory for chunk.
            std::string_view sv(&chunk[start], len);
            auto line = Utils::trimLine(sv);
            if (!line.empty()) {
                ++fi.state.lineNo;
                ++linesProcessed;
                emitIfMatch(fi.path, line, fi.state.lineNo);
            }
        } else {
            ++linesSkippedCap;
            logger::debug("[ParseEmit] Skipped oversized line: len={} cap={}", len, lineCap);
        }

        // eat newline chars
        if (end < chunk.size()) {
            if (chunk[end] == '\r' && end + 1 < chunk.size() && chunk[end + 1] == '\n')
                start = end + 2;
            else
                start = end + 1;
        }
        else {
            start = end;
        }
    }

    logger::debug("[ParseEmit] Done | linesProcessed={} linesSkippedCap={}",
        linesProcessed, linesSkippedCap);
}

void Logwatch::LogWatcher::emitIfMatch(const fs::path& file, const std::string_view& line, const uint64_t& lineNo) {
    for (const auto& [name, rx] : config.patterns) {
        if (std::regex_search(line.begin(), line.end(), rx)) {
            if (callback) {
                Match m;
                const auto fileName = Utils::toUTF8(file.filename());
                m.file = Utils::spacify(fileName);
                m.line = Utils::nukeLogLine(std::string(line));
                m.keyword = name;
                if (name == "error")        m.level = "error";
                else if (name == "warning") m.level = "warning";
                else if (name == "fail")    m.level = "fail";
                else                        m.level = "other";
                m.lineNo = lineNo;
                m.when = std::chrono::system_clock::now();
                callback(m);
            } else {
                logger::warn("[EmitMatch] Pattern '{}' matched at line {} but callback is null! file={}",
                    name, lineNo, Utils::toUTF8(file.filename()));
            }
            return; // stop after first matching pattern
        }
    }
    // Only reachable if config.patterns is empty (the 'other' catch-all always matches otherwise)
    logger::warn("[EmitMatch] No pattern matched line {} in {} - patterns list may be empty",
        lineNo, Utils::toUTF8(file.filename()));
}

void Logwatch::LogWatcher::addLogDirectories() {
    const auto gameRoot = std::filesystem::path(REL::Module::get().filename()).parent_path();
    addIfExists(gameRoot / "Data" / "SKSE" / "Plugins");

    const auto docs = GetDocumentsDir();
    if (!docs.empty()) {
        addIfExists(docs / "My Games" / "Skyrim Special Edition" / "SKSE");
        addIfExists(docs / "My Games" / "Skyrim.INI" / "SKSE");
        addIfExists(docs / "My Games" / "Skyrim Special Edition" / "SKSE" / "Plugins");
        addIfExists(docs / "My Games" / "Skyrim" / "SKSE");
        addIfExists(docs / "My Games" / "Skyrim" / "SKSE" / "Plugins");

        // Papyrus logs
        if (config.watchPapyrus) addIfExists(docs / "My Games" / "Skyrim Special Edition" / "Logs" / "Script");
    }
    else {
        logger::error("Documents folder not found");
    }
}

void Logwatch::LogWatcher::addIfExists(const std::filesystem::path& p) {

    std::error_code ec;
    const bool exists = std::filesystem::exists(p, ec);

    const auto pathToPrint = Utils::replaceUsername(Utils::toUTF8(p));

    if (ec) {
        logger::info("exists({}): {}", pathToPrint, ec.message());
        return; 
    }

    const bool is_dir = std::filesystem::is_directory(p, ec);

    if (ec) { 
        logger::info("is_directory({}): {}", pathToPrint, ec.message());
        return; 
    }

    if (exists && is_dir) {
        try {
            addDirectory(p);
            logger::info("Watching {}", pathToPrint);
        }
        catch (const std::exception& e) {
            logger::error("addDirectory({}) failed: {}", pathToPrint, e.what());
        }
    }
    else {
        logger::info("Skipping {}", pathToPrint);
    }
}

void Logwatch::LogWatcher::startLogWatcher() {
    try {
        resetNotifications();

        setWarmingUp();
        setCallback(OnMatch);
        start();

        logger::info("Watcher started with configuration:");
        config.print();
    }
    catch (const std::exception& e) {
        logger::error("Watcher start failed: {}", e.what());
    }
}