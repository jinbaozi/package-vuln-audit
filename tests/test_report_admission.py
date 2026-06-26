#!/usr/bin/env python3

def can_formal_report(status): return status in {'Validated','Needs Manual Review'}
def can_emit_poc(status): return status == 'Validated'

def main():
    for s in ['Raw Tool Hit','Candidate','Likely','Rejected']:
        assert not can_formal_report(s)
        assert not can_emit_poc(s)
    assert can_formal_report('Validated')
    assert can_emit_poc('Validated')
    assert can_formal_report('Needs Manual Review')
    assert not can_emit_poc('Needs Manual Review')
    print('report admission tests passed')
if __name__=='__main__':
    main()
