#!/Users/lovexl/yukerui/ai-chatbot/ai-chatbot/.venv/bin/python
"""Premium-gap switching backtest using AkShare ETF premium data."""
from __future__ import annotations

import argparse
import importlib.util
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd
import plotly.graph_objects as go

SKILL_SCRIPT = Path("/Users/lovexl/.codex/skills/akshare-etf-premium/scripts/etf_premium.py")


def _load_skill_module():
    if not SKILL_SCRIPT.exists():
        raise FileNotFoundError(f"Skill script not found: {SKILL_SCRIPT}")
    spec = importlib.util.spec_from_file_location("akshare_etf_premium", SKILL_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load akshare-etf-premium skill module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch_panel(symbols: List[str], start: str, end: str, adjust: str) -> pd.DataFrame:
    module = _load_skill_module()
    frames: List[pd.DataFrame] = []
    cache_dir = getattr(module, "DEFAULT_CACHE_DIR", Path(".cache"))
    cache_dir = Path(cache_dir)
    refresh = False
    for symbol in symbols:
        df = module._history_one(symbol, start, end, adjust, cache_dir=cache_dir, refresh=refresh)  # type: ignore[attr-defined]
        clean = df.drop(columns=["symbol"]).copy()
        clean = clean.rename(
            columns={
                "close": f"close_{symbol}",
                "nav": f"nav_{symbol}",
                "premium_pct": f"premium_{symbol}",
            }
        )
        frames.append(clean)

    panel = frames[0]
    for extra in frames[1:]:
        panel = panel.merge(extra, on="date", how="inner")
    panel = panel.sort_values("date").reset_index(drop=True)
    return panel


@dataclass
class Trade:
    date: pd.Timestamp
    action: str
    from_symbol: str
    to_symbol: str
    premium_diff: float
    from_price: float
    to_price: float
    portfolio_value: float


def run_strategy(
    panel: pd.DataFrame,
    initial_symbol: str,
    alt_symbol: str,
    upper: float,
    lower: float,
    capital: float,
) -> Dict[str, pd.DataFrame | float | List[Trade]]:
    if panel.empty:
        raise ValueError("No overlapping premium data for provided symbols")

    current_symbol = initial_symbol
    shares = capital / panel.loc[0, f"close_{current_symbol}"]
    trades: List[Trade] = [
        Trade(
            date=panel.loc[0, "date"],
            action="INIT",
            from_symbol="CASH",
            to_symbol=current_symbol,
            premium_diff=float(panel.loc[0, f"premium_{initial_symbol}"] - panel.loc[0, f"premium_{alt_symbol}"]),
            from_price=capital,
            to_price=float(panel.loc[0, f"close_{current_symbol}"]),
            portfolio_value=capital,
        )
    ]
    values: List[float] = []
    positions: List[str] = []

    for _, row in panel.iterrows():
        price_current = float(row[f"close_{current_symbol}"])
        portfolio_value = shares * price_current
        diff = float(row[f"premium_{initial_symbol}"] - row[f"premium_{alt_symbol}"])

        switched = False
        if current_symbol == initial_symbol and diff > upper:
            from_price = float(row[f"close_{current_symbol}"])
            value_before = shares * from_price
            shares = value_before / float(row[f"close_{alt_symbol}"])
            trades.append(
                Trade(
                    date=row["date"],
                    action="SWITCH",
                    from_symbol=initial_symbol,
                    to_symbol=alt_symbol,
                    premium_diff=diff,
                    from_price=from_price,
                    to_price=float(row[f"close_{alt_symbol}"]),
                    portfolio_value=value_before,
                )
            )
            current_symbol = alt_symbol
            switched = True
        elif current_symbol == alt_symbol and diff < lower:
            from_price = float(row[f"close_{current_symbol}"])
            value_before = shares * from_price
            shares = value_before / float(row[f"close_{initial_symbol}"])
            trades.append(
                Trade(
                    date=row["date"],
                    action="SWITCH",
                    from_symbol=alt_symbol,
                    to_symbol=initial_symbol,
                    premium_diff=diff,
                    from_price=from_price,
                    to_price=float(row[f"close_{initial_symbol}"]),
                    portfolio_value=value_before,
                )
            )
            current_symbol = initial_symbol
            switched = True

        if switched:
            price_current = float(row[f"close_{current_symbol}"])
            portfolio_value = shares * price_current

        values.append(portfolio_value)
        positions.append(current_symbol)

    equity = panel[["date"]].copy()
    equity["strategy_value"] = values
    equity["position"] = positions
    return {
        "equity": equity,
        "trades": trades,
        "final_value": values[-1],
    }


def _format_pct(x: float) -> str:
    return f"{x:.2%}" if pd.notna(x) else "-"


def _compute_metrics(values: pd.Series, capital: float, start_date: pd.Timestamp, end_date: pd.Timestamp) -> Dict[str, float]:
    final_value = float(values.iloc[-1])
    total_return = final_value / capital - 1
    years = (end_date - start_date).days / 365.25
    cagr = (final_value / capital) ** (1 / years) - 1 if years > 0 else float("nan")
    rolling_max = values.cummax()
    drawdown = values / rolling_max - 1
    max_drawdown = float(drawdown.min())
    return {
        "final_value": final_value,
        "total_return": total_return,
        "cagr": cagr,
        "max_drawdown": max_drawdown,
    }


def build_chart(panel: pd.DataFrame, equity: pd.DataFrame, symbols: List[str], capital: float) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=equity["date"],
            y=equity["strategy_value"],
            name="Premium Gap Strategy",
            line=dict(width=3, color="#1f77b4"),
        )
    )

    for symbol in symbols:
        base_price = float(panel.iloc[0][f"close_{symbol}"])
        series = capital * panel[f"close_{symbol}"] / base_price
        fig.add_trace(
            go.Scatter(
                x=panel["date"],
                y=series,
                name=f"Buy & Hold {symbol}",
                line=dict(width=1.5),
            )
        )

    markers = equity[equity["position"].ne(equity["position"].shift())]
    fig.add_trace(
        go.Scatter(
            x=markers["date"],
            y=markers["strategy_value"],
            mode="markers",
            name="Position Switch",
            marker=dict(size=8, color="#d62728"),
        )
    )

    fig.update_layout(
        title="Premium Gap Switching vs Buy & Hold",
        yaxis_title="Portfolio Value (CNY)",
        hovermode="x unified",
        template="plotly_white",
    )
    return fig


def render_html(output: Path, fig: go.Figure, summary_df: pd.DataFrame, trades_df: pd.DataFrame, metadata: Dict[str, str]) -> None:
    chart_html = fig.to_html(full_html=False, include_plotlyjs="cdn")
    summary_html = summary_df.to_html(index=False, justify="center")
    trades_html = trades_df.to_html(index=False)
    html = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>Premium Gap Strategy Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; }}
h1 {{ font-size: 24px; }}
table {{ border-collapse: collapse; margin-bottom: 24px; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: right; }}
th {{ background: #f4f4f4; }}
td:first-child, th:first-child {{ text-align: left; }}
</style>
</head>
<body>
<h1>Premium Gap Strategy Report</h1>
<p>Symbols: {metadata['symbols']} | Window: {metadata['window']} | Upper Trigger: {metadata['upper']}% | Lower Trigger: {metadata['lower']}%</p>
{summary_html}
{chart_html}
<h2>Trades</h2>
{trades_html}
</body>
</html>
"""
    output.write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Premium gap switching backtest")
    parser.add_argument("--initial-symbol", default="513100")
    parser.add_argument("--alt-symbol", default="513870")
    parser.add_argument("--initial-capital", type=float, default=100_000)
    parser.add_argument("--upper-threshold", type=float, default=2.5)
    parser.add_argument("--lower-threshold", type=float, default=1.5)
    parser.add_argument("--start", help="YYYY-MM-DD", required=True)
    parser.add_argument("--end", help="YYYY-MM-DD", required=True)
    parser.add_argument("--adjust", default="")
    parser.add_argument("--output", type=Path, default=Path("reports/premium_gap_strategy.html"))
    args = parser.parse_args()

    symbols = [args.initial_symbol, args.alt_symbol]
    start_dt = datetime.fromisoformat(args.start)
    end_dt = datetime.fromisoformat(args.end)
    start_str = start_dt.strftime("%Y%m%d")
    end_str = end_dt.strftime("%Y%m%d")

    panel = fetch_panel(symbols, start_str, end_str, args.adjust)
    result = run_strategy(panel, args.initial_symbol, args.alt_symbol, args.upper_threshold, args.lower_threshold, args.initial_capital)
    equity = result["equity"]

    comparison: List[Dict[str, float]] = []
    comp_records = []
    for label, values in [
        ("Premium Gap", equity["strategy_value"]),
        (f"Buy & Hold {args.initial_symbol}", args.initial_capital * panel[f"close_{args.initial_symbol}"] / panel.iloc[0][f"close_{args.initial_symbol}"]),
        (f"Buy & Hold {args.alt_symbol}", args.initial_capital * panel[f"close_{args.alt_symbol}"] / panel.iloc[0][f"close_{args.alt_symbol}"]),
    ]:
        metrics = _compute_metrics(values, args.initial_capital, panel.iloc[0]["date"], panel.iloc[-1]["date"])
        comp_records.append(
            {
                "Strategy": label,
                "Final Value (CNY)": f"{metrics['final_value']:,.2f}",
                "Total Return": _format_pct(metrics['total_return']),
                "CAGR": _format_pct(metrics['cagr']),
                "Max Drawdown": _format_pct(metrics['max_drawdown']),
                "Trades": len(result["trades"]) - 1 if label == "Premium Gap" else "-",
            }
        )

    summary_df = pd.DataFrame(comp_records)

    trades_df = pd.DataFrame(
        [
            {
                "Date": t.date.date().isoformat(),
                "Action": t.action,
                "From": t.from_symbol,
                "To": t.to_symbol,
                "Premium Diff (%)": f"{t.premium_diff:.2f}",
                "From Px": f"{t.from_price:.4f}",
                "To Px": f"{t.to_price:.4f}",
                "Portfolio Value": f"{t.portfolio_value:,.2f}",
            }
            for t in result["trades"]
        ]
    )

    fig = build_chart(panel, equity, symbols, args.initial_capital)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    render_html(
        args.output,
        fig,
        summary_df,
        trades_df,
        metadata={
            "symbols": ", ".join(symbols),
            "window": f"{args.start} to {args.end}",
            "upper": args.upper_threshold,
            "lower": args.lower_threshold,
        },
    )
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
