"""Passive source-interface inventory for a supplied source archive."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'code'))
from dependency_inventory import Inventory as Baseline
from dependency_mutation_guard import Inventory as Guarded


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('archive');args=parser.parse_args()
    values={name:klass(Path(args.archive)).scan() for name,klass in (('baseline',Baseline),('guarded',Guarded))}
    if values['baseline']['source_bindings']!=values['guarded']['source_bindings']:raise ValueError('source inventories differ')
    print(json.dumps(values,indent=2))
