"""Draw the paper's structural route-coverage figure from the shipped records."""
import argparse
import gzip
import json
from pathlib import Path


def counts():
    path = Path(__file__).resolve().parent / 'data/source-transfer.json.gz'
    study = json.loads(gzip.decompress(path.read_bytes()))
    totals = {mode: {
        'routes': sum(row[mode]['declared_routes'] for row in study['rows']),
        'linked': sum(row[mode]['routes_with_all_declared_direct_dependencies_linked'] for row in study['rows']),
    } for mode in ('baseline', 'guarded')}
    if totals != {'baseline': {'routes': 1591, 'linked': 564}, 'guarded': {'routes': 1591, 'linked': 757}}:
        raise ValueError('coverage records differ from the reported experiment')
    return totals


def draw(output):
    totals = counts()
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family': 'serif', 'font.size': 10, 'pdf.fonttype': 42, 'ps.fonttype': 42})
    fig, ax = plt.subplots(figsize=(6.5, 2.25), layout='constrained')
    positions = [1, 0]
    linked = [totals[mode]['linked'] for mode in totals]
    unknown = [1591 - value for value in linked]
    ax.barh(positions, linked, color='#355f86', height=.48, label='All declared direct dependencies linked')
    ax.barh(positions, unknown, left=linked, color='#cdd6de', height=.48, label='Not completely linked')
    for y, missing, complete in zip(positions, unknown, linked):
        ax.text(complete / 2, y, str(complete), ha='center', va='center', color='white')
        ax.text(complete + missing / 2, y, str(missing), ha='center', va='center', color='#1f2933')
    ax.set_yticks(positions, ['Baseline', 'Guarded'])
    ax.set_xlim(0, 1591)
    ax.set_xlabel('Declared routes in the same 48 source snapshots')
    ax.spines[['top', 'right']].set_visible(False)
    ax.legend(loc='upper center', bbox_to_anchor=(.5, 1.28), ncol=2, frameon=False, fontsize=8)
    fig.savefig(output)
    plt.close(fig)
    return totals


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(draw(args.output)))
