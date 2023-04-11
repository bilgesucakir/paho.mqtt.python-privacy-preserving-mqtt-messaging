# internal dependencies

# external dependencies
import logging
import pandas as pd


class MockCursor:
    def __init__(self, path):
        """
        Creates a MockCursor that can be used in the SqlParser instead of a jaydebeaoi Cursor
        :param path: path that we should should write the mock ran queries to
        :type path: str
        """
        self.path = path
        self.query_n=0
        self.last_query=""
        self.description = []
        pass

    #Mock the execution of a query (writes the query to a file so we can check if it was run)
    def execute(self, query):
            self.query_n += 1
            with open(self.path+"query"+str(self.query_n)+".txt", "w") as text_file:
                text_file.write(query)
            self.last_query=query

    #mock the function to get the results of a query
    def fetchall(self):
        df = pd.DataFrame([self.last_query])
        self.description = [[c] for c in df.columns]
        return df
