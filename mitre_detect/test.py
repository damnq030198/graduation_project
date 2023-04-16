from mitre import MitreParser
import unittest
import os



def get_all_rules(folder):
    files = []
    for r, d, f in os.walk(folder):
        for file in f:
            if file.endswith('.yml'):
                files.append(os.path.join(r, file))
    return files


class TestStringMethods(unittest.TestCase):

    def test_full_rule(self):
        log = {
            "EventID": 8,
            "SourceImage": r'skjdf\System32\cscript.exe',
            "TargetImage": r'lsjdflk\SysWOW64\ljsflkj',
            "StartModule": None
        }
        rules = get_all_rules("/mitre_detect_service/rules_handle")
        parsers = [MitreParser(rule) for rule in rules]
        print(len(parsers))
        for parser in parsers:
            if parser.check(log):
                info = parser.info()
                self.assertEqual(
                    info['title'], "CACTUSTORCH Remote Thread Creation")
                break

                
def get_all_rules(folder):
  files = []
  for r, d, f in os.walk(folder):
    for file in f:
        if file.endswith('.yml'):
            files.append(os.path.join(r, file))
  return files

class TestStringMethods(unittest.TestCase):

    def test_single_rule(self):
      file_path = "sigma/rules/windows/sysmon/sysmon_cactustorch.yml"
      log = {
        "EventID": 8,
        "SourceImage": r'skjdf\System32\cscript.exe',
        "TargetImage": r'lsjdflk\SysWOW64\ljsflkj',
        "StartModule": None
      }
      parser = MitreParser(file_path)
      result = parser.check(log)
      self.assertTrue(result)
      result = parser.check(log)
      self.assertTrue(result)

    def test_full_rule(self):
      log = {
        "EventID": 8,
        "SourceImage": r'skjdf\System32\cscript.exe',
        "TargetImage": r'lsjdflk\SysWOW64\ljsflkj',
        "StartModule": None
      }

      rules = get_all_rules("sigma/rules/windows/sysmon")
      parsers = [MitreParser(rule) for rule in rules]
      for parser in parsers:
        if parser.check(log):
          info = parser.info()
          self.assertEqual(info['title'], "CACTUSTORCH Remote Thread Creation")
          break


if __name__ == '__main__':
    unittest.main()
    # print(get_all_rules("sigma/rules/"))