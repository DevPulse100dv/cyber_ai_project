content = open(r'c:\Users\raksh\OneDrive\Desktop\CyberAIProject\agentic-cyber-security\admin-dashboard\src\App.jsx', encoding='utf8').read()
def check(o, c):
    oc = content.count(o)
    cc = content.count(c)
    print(f'{o} : {oc}, {c} : {cc}')
    if oc != cc: print(f'Mismatch: {o}{c}')

check('{', '}')
check('(', ')')
check('[', ']')
check('<', '>')
