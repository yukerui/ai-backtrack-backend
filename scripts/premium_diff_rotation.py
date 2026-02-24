#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import akshare as ak
import numpy as np
import pandas as pd

import importlib.util

SKILL_SCRIPT = Path("/Users/lovexl/.codex/skills/akshare-rotation-backtest/scripts/rotation_backtest.py")
SPEC = importlib.util.spec_from_file_location("skill_rotation_backtest", SKILL_SCRIPT)
SKILL = importlib.util.module_from_spec(SPEC)
if SPEC.loader is None:
    raise RuntimeError("无法载入技能脚本 rotation_backtest.py")
SPEC.loader.exec_module(SKILL)


@dataclass
class StrategyResult:
    equity: pd.Series
    positions: pd.Series
    diff: pd.Series
    premiums: pd.DataFrame
    closes: pd.DataFrame
    switches: List[Dict]


def load_close_series(symbol: str, market: str, start: str, end: str, cache_dir: Path, refresh: bool) -> pd.Series:
    return SKILL.load_series(symbol=symbol, market=market, start=start, end=end, cache_dir=cache_dir, refresh=refresh)


def load_nav_series(symbol: str, start: str, end: str) -> pd.Series:
    df = ak.fund_etf_fund_info_em(fund=symbol, start_date=start, end_date=end)
    if df.empty:
        raise RuntimeError(f"未获取到 {symbol} 的场内基金净值信息")
    df = df.rename(columns={"净值日期": "date", "单位净值": "nav"})
    df["date"] = pd.to_datetime(df["date"])
    df["nav"] = pd.to_numeric(df["nav"], errors="coerce")
    df = df.dropna().sort_values("date")
    return df.set_index("date")["nav"]


def build_panel(symbols: List[str], start: str, end: str, cache_dir: Path, refresh: bool) -> pd.DataFrame:
    panel_parts = []
    premiums = {}
    closes = {}
    for symbol in symbols:
        close_series = load_close_series(symbol, "etf", start, end, cache_dir, refresh).rename(f"close_{symbol}")
        nav_series = load_nav_series(symbol, start, end).rename(f"nav_{symbol}")
        merged = pd.concat([close_series, nav_series], axis=1).dropna()
        merged[f"premium_{symbol}"] = (merged[f"close_{symbol}"] / merged[f"nav_{symbol}"] - 1) * 100
        premiums[symbol] = merged[f"premium_{symbol}"]
        closes[symbol] = merged[f"close_{symbol}"]
        panel_parts.append(merged[[f"close_{symbol}", f"premium_{symbol}"]])
    panel = pd.concat(panel_parts, axis=1).dropna().sort_index()
    return panel, pd.DataFrame(premiums), pd.DataFrame(closes)


def perf_stats(equity: pd.Series) -> Dict[str, float]:
    ret = equity.pct_change().dropna()
    total = equity.iloc[-1] / equity.iloc[0] - 1
    days = max((equity.index[-1] - equity.index[0]).days, 1)
    cagr = (1 + total) ** (365 / days) - 1
    mdd = (equity / equity.cummax() - 1).min()
    vol = ret.std(ddof=0) * math.sqrt(252) if not ret.empty else 0.0
    sharpe = (ret.mean() / ret.std(ddof=0) * math.sqrt(252)) if ret.std(ddof=0) > 0 else 0.0
    return {
        "total_return_pct": total * 100,
        "cagr_pct": cagr * 100,
        "max_drawdown_pct": mdd * 100,
        "annual_vol_pct": vol * 100,
        "sharpe": sharpe,
    }


def run_strategy(panel: pd.DataFrame, low_th: float, high_th: float, primary: str, secondary: str) -> StrategyResult:
    diff = panel[f"premium_{primary}"] - panel[f"premium_{secondary}"]
    dates = panel.index
    positions = []
    switches: List[Dict] = []

    first_diff = diff.iloc[0]
    if first_diff < low_th:
        current = primary
    elif first_diff > high_th:
        current = secondary
    else:
        current = primary
    switches.append({
        "date": dates[0].strftime("%Y-%m-%d"),
        "action": f"初始化持有{current}",
        "diff": float(first_diff),
    })

    equity = [1.0]
    positions.append(current)
    for i in range(1, len(panel)):
        prev = panel.iloc[i - 1]
        curr = panel.iloc[i]
        ret = curr[f"close_{current}"] / prev[f"close_{current}"] - 1
        equity.append(equity[-1] * (1 + ret))

        next_pos = current
        curr_diff = diff.iloc[i]
        if curr_diff < low_th:
            next_pos = primary
        elif curr_diff > high_th:
            next_pos = secondary
        if next_pos != current:
            switches.append({
                "date": dates[i].strftime("%Y-%m-%d"),
                "action": f"切换至{next_pos}",
                "diff": float(curr_diff),
            })
        current = next_pos
        positions.append(current)

    equity_series = pd.Series(equity, index=dates, name="equity")
    position_series = pd.Series(positions, index=dates, name="position")
    return StrategyResult(equity=equity_series, positions=position_series, diff=diff, premiums=panel[[f"premium_{primary}", f"premium_{secondary}"]], closes=panel[[f"close_{primary}", f"close_{secondary}"]], switches=switches)


def build_chart_html(result: StrategyResult, primary: str, secondary: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chart_payload = {
        "dates": [d.strftime("%Y-%m-%d") for d in result.equity.index],
        "equity": [round(x, 4) for x in result.equity],
        f"price_{primary}": [round(x / result.closes[f"close_{primary}"].iloc[0], 4) for x in result.closes[f"close_{primary}"]],
        f"price_{secondary}": [round(x / result.closes[f"close_{secondary}"].iloc[0], 4) for x in result.closes[f"close_{secondary}"]],
        "diff": [round(x, 4) for x in result.diff],
        "switches": result.switches,
        "positions": result.positions.tolist(),
    }
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>513100-513870 溢价切换策略回测</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 16px; background: #0b1115; color: #f0f0f0; }}
    #backtestChart {{ width: 100%; height: 520px; }}
    h1 {{ font-weight: 600; font-size: 20px; margin-bottom: 8px; }}
    p.note {{ color: #ccc; font-size: 14px; }}
  </style>
  <script src=\"https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js\"></script>
</head>
<body>
  <h1>513100 / 513870 溢价阈值切换策略</h1>
  <p class=\"note\">区间：{result.equity.index[0].strftime('%Y-%m-%d')} 至 {result.equity.index[-1].strftime('%Y-%m-%d')}</p>
  <div id=\"backtestChart\"></div>
  <script>
    const payload = {json.dumps(chart_payload, ensure_ascii=False)};
    const chart = echarts.init(document.getElementById('backtestChart'));
    const option = {{
      backgroundColor: '#0b1115',
      tooltip: {{ trigger: 'axis' }},
      legend: {{ data: ['策略净值', '{primary}价格(归一)', '{secondary}价格(归一)', '溢价差(513100-513870)'] }},
      grid: {{ left: 60, right: 60, top: 60, bottom: 60 }},
      xAxis: {{ type: 'category', data: payload.dates, axisLabel: {{ color: '#9fb0c7' }} }},
      yAxis: [
        {{ type: 'value', name: '净值/价格', position: 'left', axisLabel: {{ color: '#9fb0c7' }} }},
        {{ type: 'value', name: '溢价差(%)', position: 'right', axisLabel: {{ color: '#9fb0c7' }} }}
      ],
      dataZoom: [{{ type: 'inside' }}, {{ type: 'slider' }}],
      series: [
        {{ name: '策略净值', type: 'line', yAxisIndex: 0, smooth: true, data: payload.equity, lineStyle: {{ width: 2 }} }},
        {{ name: '{primary}价格(归一)', type: 'line', yAxisIndex: 0, smooth: true, data: payload['price_{primary}'], lineStyle: {{ width: 1, type: 'dashed' }} }},
        {{ name: '{secondary}价格(归一)', type: 'line', yAxisIndex: 0, smooth: true, data: payload['price_{secondary}'], lineStyle: {{ width: 1, type: 'dashed' }} }},
        {{ name: '溢价差(513100-513870)', type: 'line', yAxisIndex: 1, smooth: false, data: payload.diff, lineStyle: {{ width: 1, color: '#ffb347' }} }}
      ]
    }};
    chart.setOption(option);
  </script>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="513100-513870 溢价阈值切换回测")
    parser.add_argument("--low", type=float, default=1.5, help="切换至主ETF的溢价差下限")
    parser.add_argument("--high", type=float, default=2.5, help="切换至副ETF的溢价差上限")
    parser.add_argument("--start", default="20240219", help="回测开始日期，YYYYMMDD")
    parser.add_argument("--end", default="20260219", help="回测结束日期，YYYYMMDD")
    parser.add_argument("--cache-dir", default=str(Path("artifacts/.cache")), help="价格数据缓存目录")
    parser.add_argument("--refresh", action="store_true", help="强制刷新缓存")
    parser.add_argument("--html", default="artifacts/premium_rotation_chart.html", help="图表输出路径")
    args = parser.parse_args()

    primary = "513100"
    secondary = "513870"

    panel, premium_df, close_df = build_panel([primary, secondary], args.start, args.end, Path(args.cache_dir), args.refresh)
    result = run_strategy(panel, args.low, args.high, primary, secondary)

    stats = perf_stats(result.equity)
    bh_primary = (result.closes[f"close_{primary}"] / result.closes[f"close_{primary}"].iloc[0]).rename("bh_primary")
    bh_secondary = (result.closes[f"close_{secondary}"] / result.closes[f"close_{secondary}"].iloc[0]).rename("bh_secondary")
    stats_primary = perf_stats(bh_primary)
    stats_secondary = perf_stats(bh_secondary)

    build_chart_html(result, primary, secondary, Path(args.html))

    output = {
        "strategy_stats": stats,
        f"buy_hold_{primary}": stats_primary,
        f"buy_hold_{secondary}": stats_secondary,
        "switches": result.switches,
        "chart": args.html,
        "start": result.equity.index[0].strftime("%Y-%m-%d"),
        "end": result.equity.index[-1].strftime("%Y-%m-%d"),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
