# internal dependencies
# external dependencies
import jaydebeapi
import pandas as pd




class SqlParser:

    def __init__(self, output_basepath=None, sep=",", extension=".csv", parse_comment="--:--"):
        """

        :param output_basepath: The path to the directory where the results of data queries should be written
        :type output_basepath: str
        :param sep: The separator that should should be used when writing data queries to a file
        :type sep: str
        :param extension: The file extension that should be added to data names when creating a filenamne
        :type extension: str
        """
        self.setups = []
        self.extracts = {}
        self.cleanups = []
        self.output_basepath = output_basepath
        self.username = None
        self.password = None
        self.address = None
        self.conn = None
        self.cur = None
        self.sep = sep
        self.extension = extension
        self.PARSE_COMMENT = parse_comment

    def set_credentials(self, username, password):
        """

        :param username: Database username
        :type username: str
        :param password: Database password
        :type password: str
        """
        self.username = username
        self.password = password

    def set_address(self, address):
        """
        Set the data base address
        :param address: should be ofd the form '//XX.XXX.XX.XXX/DBS_PORT=XXXX'
        :type address: str
        :return: None
        :rtype: None
        """
        self.address = address

    def open_connection(self, address = None, username = None, password = None):
        """
        Open a connection to the database, if the credentials a re not provided,
        uses the ones already provided in set functions
        :param address:
        :type address:
        :param username:
        :type username:
        :param password:
        :type password:
        :return:
        :rtype:
        """
        if not address:
            address = self.address
        if not username:
            username = self.username
        if not password:
            password = self.password

        self.conn = jaydebeapi.connect('com.teradata.jdbc.TeraDriver',
                                  'jdbc:teradata:'+address+',USER=' + username + ',PASSWORD=' + password,
                                  jars=['terajdbc4.jar','tdgssconfig.jar'])
        self.cur = self.conn.cursor()


    def parse_sql(self,path):
        """
        Parse the SQL file, separating the different queries and adding the to relevant lists (setups, extracts, cleanups)
        :param path: path to sql file
        :type path: str
        :return: None
        :rtype: None
        """
        sql_file = open(path, "r")
        sql_text = sql_file.read()

        sql_text = self.remove_block_comments(sql_text)

        # split up the different blocks of sql code (each block can contain multiple sql commands
        sql_blocks = sql_text.split(self.PARSE_COMMENT)

        # Loop through the blocks and split each into it's individual commands and execute
        for block in sql_blocks:
            # Get the setup commands
            if block.find("SETUP") > -1:
                block = block[block.find("\n"):].strip()
                commands = block.split(";")
                for command in commands:
                    command = command.strip()
                    if len(command) != 0:
                        self.setups.append(command.strip())

            # Get the Cleanup Commands
            elif block.find("CLEANUP") > -1:
                block = block[block.find("\n"):].strip()
                commands = block.split(";")
                for command in commands:
                    command = command.strip()
                    if len(command) != 0:
                        self.cleanups.append(command.strip())

            # Get the extract commands
            elif block.find("DATA") > -1:
                print("block:")
                name = block.split(":")[1].split("\n")[0].strip()
                print(name)
                block = block[block.find(name) + len(name):].strip()


                commands = block.split(";")

                for command in commands:

                    command = command.strip()
                    if len(command) != 0:
                        self.extracts[name] = command.strip()
            else:
                print("WARNING: Block type not recognizable.  Skipping block:")
                print(block)

    def remove_block_comments(self, sql):
        print("removing block comments from:")
        print(sql)
        i=0
        while (True):
            print(i)
            start = sql.find("/*")
            print(start)
            if start == -1:
                break
            end = sql.find("*/")
            print(end)
            if end == -1:
                print("ERROR: unclosed block comment")
                break
            sql = sql.replace(sql[start:end + 2], "")
            i=i+1

        return sql

    def run_setups(self):
        """
        Run all of the setup commands
        :return: None
        :rtype: None
        """
        for setup in self.setups:
            print("setup:")
            #print(setup)
            self.cur.execute(setup)

    def run_extracts(self, write_to_file = True, return_results = False ):
        """
        Run all of the data extract commands
        :param write_to_file: Should the data be written to a file?
        :type write_to_file: Bool
        :param return_results: Should the extracted data be returned?
        :type return_results: Bool
        :return: None or data results
        :rtype: None or pd.DataFrame
        """
        out_dict={}
        for name, extract in self.extracts.items():
            print("name:", name)
            print("extract:")
            #print(extract)
            self.cur.execute(extract)
            data = pd.DataFrame(self.cur.fetchall())
            print(data.shape)
            print(data.head())
            print(self.cur.description)
            print([d[0] for d in self.cur.description])
            print(data.columns)
            data.columns = [d[0] for d in self.cur.description]
            if return_results:
                out_dict[name] = data
            if write_to_file:
                data.to_csv(self.output_basepath+"/"+name+self.extension, sep=self.sep, index=False)
        if return_results:
            return out_dict

    def run_cleanups(self):
        """
        Run all of the  cleanup commands
        :return: None
        :rtype: None
        """
        for cleanup in self.cleanups:
            print("cleanup:")
            #print(cleanup)
            self.cur.execute(cleanup)

    def run_all(self):
        """
        Run all commands
        :return: None
        :rtype: None
        """
        self.run_setups()
        self.run_extracts(write_to_file=True, return_results=False)
        self.run_cleanups()

    def clear_all(self):
        self.setups = []
        self.extracts = {}
        self.cleanups = []

# Question what do do with parameters that need to be changed (i.e. dates) and macros?