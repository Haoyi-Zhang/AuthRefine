"""Passive source-interface inventory for a supplied source archive."""
import argparse
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'code'))
from dependency_inventory import Inventory as Baseline
from dependency_mutation_guard import Inventory as Guarded


def validate_archive(path):
    """Admit one bounded, unambiguous snapshot without extracting its files."""
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('source archive exceeds the input-size limit')
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > 50000:
            raise ValueError('source archive exceeds the member-count limit')
        seen=set();roots=set()
        for item in archive.infolist():
            name=item.orig_filename;member=PurePosixPath(name)
            if (name in seen or member.is_absolute() or '..' in member.parts
                    or name.endswith('.py') and ('\\' in name or ':' in name)
                    or item.flag_bits & 1):
                raise ValueError('ambiguous, unsafe or encrypted source member')
            seen.add(name)
            if not item.is_dir():
                if len(member.parts)<2:
                    raise ValueError('source files require one enclosing snapshot directory')
                roots.add(member.parts[0])
        if len(roots)!=1:
            raise ValueError('source files require exactly one snapshot directory')
        try:archive.comment.decode('ascii')
        except UnicodeError as error:raise ValueError('snapshot comment must be ASCII') from error


def route_key(route):
    return route['member'],route['function'],route['line'],route['method']


def summarize(report):
    routes=report['routes'];declared=[r for r in routes if r['dependencies']]
    complete=sum(all(e['resolved_source_node'] is not None for e in r['dependencies']) for r in declared)
    return dict(declared_routes=len(routes),routes_with_explicit_dependencies=len(declared),
        routes_without_explicit_dependencies=len(routes)-len(declared),
        routes_with_all_declared_direct_dependencies_linked=complete,
        routes_with_unresolved_declared_dependencies=len(declared)-complete,
        syntax_gap_files=len(report['syntax_errors']),bounded_omitted_files=len(report['omitted']),
        status='static_routes_found' if routes else 'unsupported_framework_or_route_form')


def analyze_archive(path):
    path=Path(path);validate_archive(path)
    values={name:klass(path).scan() for name,klass in (('baseline',Baseline),('guarded',Guarded))}
    a,b=values['baseline'],values['guarded']
    if (any(a[key]!=b[key] for key in ('source_bindings','snapshot','archive_sha256'))
            or sorted(map(route_key,a['routes']))!=sorted(map(route_key,b['routes']))):
        raise ValueError('paired source inventory or route denominator differs')
    summaries={name:summarize(value) for name,value in values.items()}
    return dict(**values,summary=summaries,
        fully_linked_declared_route_delta=summaries['guarded']['routes_with_all_declared_direct_dependencies_linked']
            -summaries['baseline']['routes_with_all_declared_direct_dependencies_linked'],
        input_parser=dict(implementation=sys.implementation.name,release=list(sys.version_info[:3])),
        source_modules_or_tests_executed=False,semantic_authorization_verdict=None,
        scope='Paired static source links only; zero routes or unresolved links are not authorization success.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive');args=parser.parse_args(argv)
    try:result=analyze_archive(args.archive)
    except (OSError,ValueError,zipfile.BadZipFile,RecursionError) as error:
        parser.exit(2,'source input not admitted: '+str(error)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
