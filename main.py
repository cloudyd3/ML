import json
import re
import pandas as pd


def calc_features():
    with open('events.json', 'r', encoding='utf8') as f:
        data = json.loads(f.read())

    df = pd.json_normalize(data)
    df = df.drop(['output'], axis=1)
    for s in ['is_run_as_root', 'is_bash_in_args', 'is_sh_in_args', 'is_passwd_in_open_args',
                      'is_proc_in_open_args', 'n_failed_syscalls']:
        df[s] = 0

    for index, row in df.iterrows():
        if row['is_run_as_root'] == 0 and row['output_fields.user.name'] == 'root':
            df.at[index, 'is_run_as_root'] = 1
        if row['is_bash_in_args'] == 0 and re.compile('.*/+bin/+bash.*').match(row['output_fields.proc.cmdline']):
            df.at[index, 'is_bash_in_args'] = 1
        if row['is_sh_in_args'] == 0 and re.compile('.*/+bin/+sh.*').match(row['output_fields.proc.cmdline']):
            df.at[index, 'is_sh_in_args'] = 1
        if row['is_passwd_in_open_args'] == 0 and re.compile('.*/+etc/+passwd.*').match(row['output_fields.proc.cmdline']):
            df.at[index, 'is_passwd_in_open_args'] = 1
        if row['is_proc_in_open_args'] == 0 and re.compile('.*/+proc.*').match(row['output_fields.proc.cmdline']):
            df.at[index, 'is_proc_in_open_args'] = 1
    df.to_csv('events.csv', encoding='utf-8')


if __name__ == '__main__':
    calc_features()
