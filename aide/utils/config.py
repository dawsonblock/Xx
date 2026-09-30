"""configuration and setup utils"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Hashable, cast

import coolname
import rich
from omegaconf import OmegaConf
from rich.syntax import Syntax
import shutup
from rich.logging import RichHandler
import logging

from . import tree_export
from . import copytree, preproc_data, serialize

shutup.mute_warnings()
logging.basicConfig(
    level="WARNING", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)
logger = logging.getLogger("aide")
logger.setLevel(logging.WARNING)


""" these dataclasses are just for type hinting, the actual config is in config.yaml """


@dataclass
class StageConfig:
    model: str
    temp: float | None


@dataclass
class SearchConfig:
    max_debug_depth: int
    debug_prob: float
    num_drafts: int


@dataclass
class AgentConfig:
    steps: int
    k_fold_validation: int
    expose_prediction: bool
    data_preview: bool
    code: StageConfig
    feedback: StageConfig

    search: SearchConfig
    metric_maximize: bool | None = None


@dataclass
class RSIEvolutionConfig:
    population: int = 48
    generations: int = 5
    elite_count: int = 8
    seed: int = 0
    work_penalty: float = 0.10
    parallel_bonus: float = 0.0
    min_validation_margin: float = 0.0
    max_qualification_regression: float = 0.01
    max_single_world_regression: float = 0.05
    min_qualification_worlds: int = 3
    use_llm_developer: bool = False
    llm_candidates: int = 4
    llm_model: str | None = None
    llm_temp: float = 0.4
    beta_grid: list[float] = field(default_factory=lambda: [0.2, 0.4, 0.6, 0.8, 1.0])


@dataclass
class RSISandboxConfig:
    mode: str = "strict"
    backend: str = "auto"
    container_runtime: str = "auto"
    container_image: str | None = None
    allow_insecure_process: bool = False
    memory_mb: int = 32768
    seatbelt_memory_mb: int = 1024
    cpu_seconds: int = 0
    file_size_mb: int = 2048
    workspace_mb: int = 2048
    max_output_mb: int = 16
    nproc: int = 128
    nofile: int = 256


@dataclass
class RSIJevConfig:
    # LocalJevFabric/SystemOne is optional and advisory by default.
    enabled: bool = False
    endpoint: str = "http://127.0.0.1:8090/v1/systemone"
    model: str = "local-jev-fabric"
    api_key_env: str = "FABRIC_API_KEY"
    timeout_s: float = 1.5
    confidence_threshold: float = 0.72
    fail_open: bool = True
    max_state_chars: int = 12000
    # Only high-confidence failure repairability can influence search.  The
    # remaining JEV decisions are shadow telemetry until separately qualified.
    failure_classification: bool = True
    failure_influence: bool = False
    shadow_action_ranking: bool = True
    shadow_model_routing: bool = False
    shadow_verification_depth: bool = False


@dataclass
class RSICanaryConfig:
    attempts: int = 4
    repeats: int = 3
    min_pass_fraction: float = 0.66
    max_normalized_regression: float = 0.05
    min_valid: int = 1
    score_scale_floor: float = 1.0


@dataclass
class RSIConfig:
    enabled: bool = False
    outer_rounds: int = 5
    steps_per_round: int = 24
    max_parallelism: int = 1
    fallback_width: int = 6
    fallback_depth: int = 8
    hard_max_width: int = 24
    hard_max_depth: int = 32
    split_epoch: str = "0001"
    memory_mode: str = "none"
    resume_log_dir: str | None = None
    sandbox: RSISandboxConfig = field(default_factory=RSISandboxConfig)
    canary: RSICanaryConfig = field(default_factory=RSICanaryConfig)
    jev: RSIJevConfig = field(default_factory=RSIJevConfig)
    evolution: RSIEvolutionConfig = field(default_factory=RSIEvolutionConfig)


@dataclass
class ExecConfig:
    timeout: int
    agent_file_name: str
    format_tb_ipython: bool


@dataclass
class Config(Hashable):
    data_dir: Path
    desc_file: Path | None

    goal: str | None
    eval: str | None

    log_dir: Path
    workspace_dir: Path

    preprocess_data: bool
    copy_data: bool

    exp_name: str

    exec: ExecConfig
    generate_report: bool
    report: StageConfig
    agent: AgentConfig
    rsi: RSIConfig = field(default_factory=RSIConfig)


def _get_next_logindex(dir: Path) -> int:
    """Get the next available index for a log directory."""
    max_index = -1
    for p in dir.iterdir():
        try:
            current_index = int(p.name.split("-")[0])
            if current_index > max_index:
                max_index = current_index
        except ValueError:
            pass
    return max_index + 1


def _load_cfg(
    path: Path = Path(__file__).parent / "config.yaml", use_cli_args=True
) -> Config:
    cfg = OmegaConf.load(path)
    if use_cli_args:
        cfg = OmegaConf.merge(cfg, OmegaConf.from_cli())
    return cfg


def load_cfg(path: Path = Path(__file__).parent / "config.yaml") -> Config:
    """Load config from .yaml file and CLI args, and set up logging directory."""
    return prep_cfg(_load_cfg(path))


def prep_cfg(cfg: Config):
    if cfg.data_dir is None:
        raise ValueError("`data_dir` must be provided.")

    if cfg.desc_file is None and cfg.goal is None:
        raise ValueError(
            "You must provide either a description of the task goal (`goal=...`) or a path to a plaintext file containing the description (`desc_file=...`)."
        )

    if cfg.data_dir.startswith("example_tasks/"):
        cfg.data_dir = Path(__file__).parent.parent / cfg.data_dir
    cfg.data_dir = Path(cfg.data_dir).resolve()

    if cfg.desc_file is not None:
        cfg.desc_file = Path(cfg.desc_file).resolve()

    # Resume an existing RSI experiment without allocating a new experiment id.
    resume_log_dir = None
    try:
        resume_log_dir = cfg.rsi.resume_log_dir
    except Exception:
        pass
    if resume_log_dir:
        import json

        resume_log = Path(resume_log_dir).resolve()
        state_path = resume_log / "rsi" / "state.json"
        if not state_path.exists():
            raise ValueError(f"cannot resume: missing {state_path}")
        state = json.loads(state_path.read_text())
        base_workspace = state.get("base_workspace")
        if not base_workspace:
            raise ValueError("cannot resume: state.json has no base_workspace")
        cfg.log_dir = resume_log
        cfg.workspace_dir = Path(base_workspace).resolve()
        cfg.exp_name = resume_log.name
        cfg_schema: Config = OmegaConf.structured(Config)
        cfg = OmegaConf.merge(cfg_schema, cfg)
        return cast(Config, cfg)

    top_log_dir = Path(cfg.log_dir).resolve()
    top_log_dir.mkdir(parents=True, exist_ok=True)

    top_workspace_dir = Path(cfg.workspace_dir).resolve()
    top_workspace_dir.mkdir(parents=True, exist_ok=True)

    # generate experiment name and prefix with consecutive index
    ind = max(_get_next_logindex(top_log_dir), _get_next_logindex(top_workspace_dir))
    cfg.exp_name = cfg.exp_name or coolname.generate_slug(3)
    cfg.exp_name = f"{ind}-{cfg.exp_name}"

    cfg.log_dir = (top_log_dir / cfg.exp_name).resolve()
    cfg.workspace_dir = (top_workspace_dir / cfg.exp_name).resolve()

    # validate the config
    cfg_schema: Config = OmegaConf.structured(Config)
    cfg = OmegaConf.merge(cfg_schema, cfg)

    return cast(Config, cfg)


def print_cfg(cfg: Config) -> None:
    rich.print(Syntax(OmegaConf.to_yaml(cfg), "yaml", theme="paraiso-dark"))


def load_task_desc(cfg: Config):
    """Load task description from markdown file or config str."""

    # either load the task description from a file
    if cfg.desc_file is not None:
        if not (cfg.goal is None and cfg.eval is None):
            logger.warning(
                "Ignoring goal and eval args because task description file is provided."
            )

        with open(cfg.desc_file) as f:
            return f.read()

    # or generate it from the goal and eval args
    if cfg.goal is None:
        raise ValueError(
            "`goal` (and optionally `eval`) must be provided if a task description file is not provided."
        )

    task_desc = {"Task goal": cfg.goal}
    if cfg.eval is not None:
        task_desc["Task evaluation"] = cfg.eval

    return task_desc


def prep_agent_workspace(cfg: Config):
    """Setup the agent's workspace and preprocess data if necessary."""
    (cfg.workspace_dir / "input").mkdir(parents=True, exist_ok=True)
    (cfg.workspace_dir / "working").mkdir(parents=True, exist_ok=True)

    copytree(cfg.data_dir, cfg.workspace_dir / "input", use_symlinks=not cfg.copy_data)
    if cfg.preprocess_data:
        preproc_data(cfg.workspace_dir / "input")


def save_run(cfg: Config, journal):
    cfg.log_dir.mkdir(parents=True, exist_ok=True)

    # save journal
    serialize.dump_json(journal, cfg.log_dir / "journal.json")
    # save config
    OmegaConf.save(config=cfg, f=cfg.log_dir / "config.yaml")
    # create the tree + code visualization
    tree_export.generate(cfg, journal, cfg.log_dir / "tree_plot.html")
    # save the best found solution
    best_node = journal.get_best_node(only_good=False)
    with open(cfg.log_dir / "best_solution.py", "w") as f:
        f.write(best_node.code)
