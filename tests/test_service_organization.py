"""Ensure service extraction cannot reorder exceptions or spread rule options."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from organize_active_surge import build

class OrganizationTests(unittest.TestCase):
    def test_service_grouping_preserves_other_sections(self):
        source='[General]\nloglevel = notify\n[Rule]\nDOMAIN-SUFFIX,openai.com,SCHOLAR,extended-matching\nDOMAIN-SUFFIX,chatgpt.com,SCHOLAR,extended-matching\nFINAL,PROXY,dns-failed\n[Host]\nlocalhost = 127.0.0.1\n'
        result,files,report=build(source,'services')
        self.assertEqual(report['organized_rules'],2)
        self.assertIn('RULE-SET,services/openai.list,SCHOLAR,extended-matching',result)
        self.assertIn('DOMAIN-SUFFIX,chatgpt.com',files['openai.list'])
        self.assertTrue(result.endswith('[Host]\nlocalhost = 127.0.0.1\n'))

    def test_noncontiguous_service_is_not_moved(self):
        source='[Rule]\nDOMAIN,gemini.google.com,SCHOLAR,extended-matching\nDOMAIN-SUFFIX,openai.com,SCHOLAR,extended-matching\nDOMAIN-WILDCARD,*-aiplatform.googleapis.com,SCHOLAR,extended-matching\nFINAL,PROXY\n'
        result,files,_=build(source,'services')
        self.assertLess(result.index('gemini.list'),result.index('openai.list'))
        self.assertLess(result.index('openai.list'),result.index('gemini-part02.list'))
        self.assertEqual(len(files),3)

    def test_different_flags_are_separate(self):
        source='[Rule]\nDOMAIN-SUFFIX,openai.com,SCHOLAR,extended-matching\nDOMAIN-SUFFIX,chatgpt.com,SCHOLAR\nFINAL,PROXY\n'
        _,files,report=build(source,'services')
        self.assertEqual(len(files),2)
        self.assertEqual(report['lists'][0]['options'],['extended-matching'])
        self.assertEqual(report['lists'][1]['options'],[])

    def test_unknown_service_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'Unclassified'):
            build('[Rule]\nDOMAIN,unknown-service.test,PROXY\nFINAL,PROXY\n','services')

if __name__=='__main__':unittest.main()
