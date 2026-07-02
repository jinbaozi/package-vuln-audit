#!/usr/bin/env python3

def can_formal_report(status): return status in {'Validated','Needs Manual Review'}
def can_emit_verified_poc(status): return status == 'Validated'
def can_emit_draft_poc(status): return status == 'Needs Manual Review'

def main():
    for s in ['Raw Tool Hit','Candidate','Likely','Rejected']:
        assert not can_formal_report(s)
        assert not can_emit_verified_poc(s)
        assert not can_emit_draft_poc(s)
    assert can_formal_report('Validated')
    assert can_emit_verified_poc('Validated')
    assert not can_emit_draft_poc('Validated')
    assert can_formal_report('Needs Manual Review')
    assert not can_emit_verified_poc('Needs Manual Review')
    assert can_emit_draft_poc('Needs Manual Review')
    print('report admission tests passed')
if __name__=='__main__':
    main()
