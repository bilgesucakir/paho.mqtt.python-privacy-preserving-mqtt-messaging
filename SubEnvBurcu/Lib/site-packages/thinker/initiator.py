
# Rethinkdb wrapper for asyncio
# https://github.com/mehmetkose/thinker

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2016 Mehmet Kose mehmet@linux.com

import rethinkdb as r

async def create_tables(scheme, connection):
    try:
        await r.db_create(scheme['db']).run(connection)
        print('Database created: %s' % (scheme['db']))
    except:
        pass

    for table_name in scheme['tables'].keys():
        try:
            await r.db(scheme['db']).table_create(
                table_name, durability='hard').run(connection)
            print('Table created: %s' % (table_name))
        except:
            pass

    for table_name in scheme['tables'].keys():
        for table_key in scheme['tables'][table_name].keys():
            if 'specs' in scheme['tables'][table_name][table_key]:
                specs = scheme['tables'][table_name][table_key]['specs']
                if 'index' in specs:
                    try:
                        await r.db(scheme['db']).table(table_name).index_create(table_key).run(connection)
                    except:
                        pass
                elif 'multiple_index' in specs:
                    try:
                        await r.db(scheme['db']).table(table_name).index_create(table_key, multi=True).run(connection)
                    except:
                        pass
