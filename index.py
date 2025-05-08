import requests
import re
import sys


def sign_in(account_pwd_list):
    for i in account_pwd_list:
        # 开始登录
        try:
            # 检查账号密码格式
            if '--' not in i:
                print(f"跳过格式错误的账号密码: {i} (缺少'--'分隔符)")
                continue

            parts = i.split('--')
            if len(parts) != 2:
                print(f"跳过格式错误的账号密码: {i} (分隔后不是两部分)")
                continue

            user, pwd = parts

            print(f"正在处理用户: {user}")
            r = requests.get('https://bbs.binmt.cc/misc.php?mod=mobile', timeout=5)
            aa = r.text
            bb = r.cookies
            test1 = r'saltkey=(.*?) for'
            saltkey = re.findall(test1, str(bb))[0]
            rule = r'formhash=(.*?)&amp'
            formhash = re.findall(rule, aa)[0]
            P1 = ('formhash=' + formhash + (
                '&referer=https%3A%2F%2Fbbs.binmt.cc%2Fk_misign-sign.html&fastloginfield=username'
                '&cookietime=31104000&username=') + user + '&password=' + pwd +
                  '&questionid=0&answer=&submit=true')
            headers1 = {
                'cookie': 'cQWy_2132_saltkey=' + saltkey,
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
            }
            res = requests.post(
                'https://bbs.binmt.cc/member.php?mod=logging&action=login&loginsubmit=yes&loginhash=&handlekey=loginform'
                '&inajax=1',
                data=P1, headers=headers1, timeout=5)
            cx = res.text
            cv = res.cookies
            testx = r"sign-sign.html', '(.*?)，现在将转入登录"
            test2 = r'cQWy_2132_auth=(.*?) for bbs.binmt.cc'
            cQWy_2132_auth = re.findall(test2, str(cv))[0]
            logn = re.findall(testx, str(cx))[0]
            print(f"用户 {user} 登录: {logn}")

            # 获取Formhash
            headers2 = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                          'application/signed-exchange;v=b3;q=0.9',
                'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + cQWy_2132_auth
            }
            r1 = requests.get('https://bbs.binmt.cc/k_misign-sign.html', headers=headers2, timeout=5)
            cc = r1.text
            rule11 = r'formhash=(.*?)&amp'
            formhash11 = re.findall(rule11, cc)[0]

            ##签到
            P3 = {
                'operation': 'qiandao',
                'formhash': formhash11,
                'cookie': 'cQWy_2132_saltkey=' + saltkey + ';cQWy_2132_auth=' + cQWy_2132_auth
            }
            headers3 = {
                'cookie': P3['cookie']
            }

            res = requests.get('https://bbs.binmt.cc/k_misign-sign.html', params=P3, headers=headers3, timeout=5)
            if res.status_code == 200:
                r = res.text
                z = r"(?<=CDATA).*?.\]"
                m = re.search(z, r)
                print(f'用户 {user} 签到结果:', m[0] if m else "签到失败")
        except Exception as e:
            print(f"处理过程中出错: {str(e)}")


def parse_command_line():
    """解析命令行参数，返回账号密码列表"""
    # 打印接收到的命令行参数，便于调试
    print(f"接收到的命令行参数: {sys.argv[1:]}")

    # 检查参数数量
    if len(sys.argv) <= 1:
        return []

    # 获取命令行参数
    arg_str = ' '.join(sys.argv[1:])

    # 最重要的处理方式：将输入按换行符分割（用于GitHub Actions环境变量）
    # 这种格式是一行一个账号密码，非常适合从环境变量传入
    if '\n' in arg_str:
        accounts = []
        for line in arg_str.strip().split('\n'):
            line = line.strip()
            if line:
                accounts.append(line)
        if accounts:
            return accounts

    # PowerShell特殊处理：检查是否将方括号分开了
    if len(sys.argv) >= 3:
        # 检查第一个参数是否以[开头，最后一个是否以]结尾
        if sys.argv[1].startswith('[') and sys.argv[-1].endswith(']'):
            # 将所有参数合并，移除首尾的方括号
            combined = ' '.join(sys.argv[1:])
            # 移除首尾的方括号
            combined = combined[1:-1].strip()
            # 分割成个别账号密码
            accounts = []
            for item in combined.split(','):
                item = item.strip()
                if item:
                    accounts.append(item)
            return accounts

    # 处理普通逗号分隔的情况
    if ',' in arg_str:
        accounts = []
        for item in arg_str.split(','):
            item = item.strip()
            if item:
                accounts.append(item)
        return accounts

    # 处理空格分隔的情况（多个账号密码直接用空格分隔）
    if ' ' in arg_str and '--' in arg_str:
        accounts = []
        for item in arg_str.split():
            if '--' in item:
                accounts.append(item.strip())
        if accounts:
            return accounts

    # 保留原始的数组处理逻辑，以防万一
    if arg_str.startswith('[') and arg_str.endswith(']'):
        # 处理方括号格式
        content = arg_str[1:-1].strip()
        if not content:
            return []

        accounts = []
        for item in content.split(','):
            item = item.strip().strip('"\'')  # 移除引号
            if item:
                accounts.append(item)
        return accounts

    elif arg_str.startswith('{') and arg_str.endswith('}'):
        # 处理花括号格式
        content = arg_str[1:-1].strip()
        if not content:
            return []

        accounts = []
        for item in content.split(','):
            item = item.strip().strip('"\'')  # 移除引号
            if item:
                accounts.append(item)
        return accounts

    # 如果没有识别出多个账号，但参数有效，视为单个账号密码
    if '--' in arg_str:
        return [arg_str.strip()]

    # 如果都不匹配，返回空列表
    return []


if __name__ == "__main__":
    account_pwd_list = parse_command_line()

    if account_pwd_list:
        print(f"解析出的账号密码列表: {account_pwd_list}")
        sign_in(account_pwd_list)
    else:
        print("请提供账号密码列表参数")
        print("用法示例:")
        print("1. 一行一个账号密码（GitHub Actions环境变量格式）:")
