# internal dependencies
from tests.mock_jaydebeapi import MockCursor

from SqlParser import SqlParser

# external  dependencies
import glob
import os
import os.path
from unittest import TestCase
import pandas as pd




class TestSqlParser(TestCase):

    def test_parse(self):
        parser = SqlParser(output_basepath="tests/output")

        parser.parse_sql("tests/resources/test_sql1.sql")

        expected_setups = ["SETUP 1", "SETUP 2", "SETUP 3", "SETUP 4"]
        expected_extracts = {"current":"DATA QUERY 1","tracked_failures_detail_bad":"DATA QUERY 2"}
        expected_cleanups = ["CLEANUP 1"]


        self.assertListEqual(parser.setups, expected_setups)
        self.assertDictEqual(parser.extracts, expected_extracts)
        self.assertListEqual(parser.cleanups, expected_cleanups)


    def test_run_all(self):
        self.cleanup()
        parser = SqlParser(output_basepath="tests/output")
        #use a MockCursor to fake a connection to a data bases.  Rather than running queries it rights them to a file and returns them
        curr = MockCursor(path="tests/output/")
        parser.cur = curr

        parser.parse_sql("tests/resources/test_sql2.sql")
        parser.run_all()



        parser.run_all()

        expected_data1 = "DATA QUERY 1"
        expected_data2 = "DATA QUERY 2"

        #check setup query got written to a file
        with open("tests/output/query1.txt", "r") as text_file:
            q_text = text_file.read()
            self.assertEquals(q_text, "SETUP 1")


        #check the data queries
        df = pd.read_csv("tests/output/current.csv")
        self.assertEquals(df.iloc[0,0], expected_data1)

        df = pd.read_csv("tests/output/tracked_failures_detail_bad.csv")
        self.assertEquals(df.iloc[0, 0], expected_data2)

        #check the cleanup query
        with open("tests/output/query4.txt", "r") as text_file:
            q_text = text_file.read()
            self.assertEquals(q_text, "CLEANUP 1")
        self.cleanup()


    def cleanup(self):
        filelist = glob.glob("tests/output/*.txt")
        for f in filelist:
            os.remove(f)
        filelist = glob.glob("tests/output/*.csv")
        for f in filelist:
            os.remove(f)

