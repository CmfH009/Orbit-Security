"""Orbit Security Local PC Tools and Skill Adapters.

High-performance adapters leveraging native system CLI tools and skills:
- EverythingSearcher: Sub-5ms NTFS file/secret/cert index search (es.exe).
- XHProbe: Fast HTTP/TLS reconnaissance and certificate inspection (xh.exe/xhs.exe).
- ADHXClient: Headless structured X/Twitter post and IOC extractor (ADHX API).
- DuckDBEngine: OLAP analytics engine for DNS telemetry, CVE feeds, and scans (duckdb.exe / duckdb).
- AttackTree: Attack tree DAG modeling and Mermaid generation (attack-tree-construction).
- FFmpegRenderer: Cyber terminal radar teaser and video/GIF renderer (ffmpeg.exe / ffprobe.exe).
- YTThreatHarvester: Media harvester for security conference talks & exploit walkthroughs (yt-dlp.exe).
"""

from orbit_security.tools.everything_search import (
    EverythingIPCError,
    EverythingNotInstalledError,
    EverythingSearchError,
    EverythingSearcher,
    SearchResult,
    default_searcher,
    search_files,
)
from orbit_security.tools.xh_probe import (
    CertificateInfo,
    ProbeResult,
    SecurityHeaderAudit,
    XHNotInstalledError,
    XHProbe,
    XHProbeError,
    default_probe,
    probe_target,
)
from orbit_security.tools.adhx_client import (
    ADHXClient,
    ADHXError,
    ArticleInfo,
    AuthorInfo,
    EngagementMetrics,
    InvalidTweetURLError,
    ThreatIntelExtraction,
    TweetData,
    TweetNotFoundError,
    default_client,
    get_x_post,
)
from orbit_security.tools.duckdb_analytics import (
    DuckDBAnalyticsError,
    DuckDBEngine,
    DuckDBNotInstalledError,
    DuckDBQueryError,
    default_duckdb,
    run_analytics_query,
)
from orbit_security.tools.attack_tree import (
    AttackAttributes,
    AttackNode,
    AttackPathAnalyzer,
    AttackTree,
    AttackTreeBuilder,
    Cost,
    DetectionRisk,
    Difficulty,
    MermaidExporter,
    NodeType,
    from_osint_findings,
    tree_to_mermaid,
)
from orbit_security.tools.ffmpeg_renderer import (
    FFmpegError,
    FFmpegNotInstalledError,
    FFmpegRenderer,
    MediaInfo,
    MediaStream,
    default_renderer,
)
from orbit_security.tools.yt_threat_harvester import (
    HarvestResult,
    VideoExtractionError,
    VideoMetadata,
    YTDLPError,
    YTDLPNotInstalledError,
    YTThreatHarvester,
    default_harvester,
)

__all__ = [
    # Everything Search
    "EverythingSearcher",
    "SearchResult",
    "EverythingSearchError",
    "EverythingNotInstalledError",
    "EverythingIPCError",
    "default_searcher",
    "search_files",
    # XH Probe
    "XHProbe",
    "ProbeResult",
    "CertificateInfo",
    "SecurityHeaderAudit",
    "XHProbeError",
    "XHNotInstalledError",
    "default_probe",
    "probe_target",
    # ADHX Client
    "ADHXClient",
    "TweetData",
    "AuthorInfo",
    "EngagementMetrics",
    "ArticleInfo",
    "ThreatIntelExtraction",
    "ADHXError",
    "InvalidTweetURLError",
    "TweetNotFoundError",
    "default_client",
    "get_x_post",
    # DuckDB Analytics
    "DuckDBEngine",
    "DuckDBAnalyticsError",
    "DuckDBNotInstalledError",
    "DuckDBQueryError",
    "default_duckdb",
    "run_analytics_query",
    # Attack Tree
    "AttackTree",
    "AttackNode",
    "NodeType",
    "Difficulty",
    "Cost",
    "DetectionRisk",
    "AttackAttributes",
    "AttackTreeBuilder",
    "MermaidExporter",
    "AttackPathAnalyzer",
    "from_osint_findings",
    "tree_to_mermaid",
    # FFmpeg Renderer
    "FFmpegRenderer",
    "MediaInfo",
    "MediaStream",
    "FFmpegError",
    "FFmpegNotInstalledError",
    "default_renderer",
    # YT Threat Harvester
    "YTThreatHarvester",
    "VideoMetadata",
    "HarvestResult",
    "YTDLPError",
    "YTDLPNotInstalledError",
    "VideoExtractionError",
    "default_harvester",
]
