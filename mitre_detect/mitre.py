import os
import yaml

class MitreParser:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path) as f:
            self.raw_rule = f.read()

    def simple_operator(self, left, right, operator):
        if operator == '=':
            if isinstance(right, str):
                if right[0] == '*' and right[-1] == '*':
                    return self.simple_operator(left, right[1:-1], "contains")
                if right[0] == '*':
                    return self.simple_operator(left, right[1:], "endswith")
                if right[-1] == '*':
                    return self.simple_operator(left, right[:-1], "startswith")
            return left == right
        if left == None:
            return False
        if operator == "endswith":
            return left.endswith(right)
        if operator == 'startswith':
            return left.startswith(right)
        if operator == 'contains':
            return right in left
        print('log: outstanding move: ', self.file_path)

    def and_operator(self, operands):
        if False in operands:
            return False
        return True

    def or_operator(self, operands):
        if True in operands:
            return True
        return False

    def get_all_detection(self, yaml_data):
        list_detection = []
        for line in yaml_data:
            for key, value in line.items():
                if key == 'detection':
                    list_detection.append(value)
        return list_detection

    def get_all_selection(self, detections):
        result = {}
        for detection in detections:
            for key, value in detection.items():
                result[key] = value
        return result

    def check_many(self, key, values):
        ls = []
        for value in values:
            v = self.check_single(key, value)
            ls.append(v)
        return self.or_operator(ls)

    def check_single(self, key, value):
        elements = key.split('|')
        field = elements[0]
        if field not in self.log:
            return False
        if len(elements) > 2:
            print('log: more than 3 elements in key: ', self.file_path)
        if len(elements) == 1:
            return self.simple_operator(self.log[field], value, '=')
        condition = elements[1]
        return self.simple_operator(self.log[field], value, condition)

    def selection_operator(self, selection):
        if isinstance(selection, list):
            ls = []
            for element in selection:
                result = self.selection_operator(element)
                ls.append(result)
            return self.or_operator(ls)

        if isinstance(selection, dict):
            ls = []
            for key, value in selection.items():
                if key == 'condition':
                    continue
                if isinstance(value, list):
                    result = self.check_many(key, value)
                    ls.append(result)
                else:
                    result = self.check_single(key, value)
                    ls.append(result)
            return self.and_operator(ls)

    def detection_operator(self, selections):
        table = {}
        condition = ''
        for key, value in selections.items():
            if key != 'condition':
                table[key] = self.selection_operator(value)
            else:
                condition = value
        if condition == "":
            print('log: null condition:', self.file_path)
        elif ('1 of combination*' in condition):
            print('log: 1 of combination*:', self.file_path)
        elif ('selector | near dllload1 and dllload2 and not exclusion' in condition):
            print('log: near:', self.file_path)
        elif ('(dns_answer and filter_int_ip) and (dns_answer and not filter_int_ip) | count(QueryName) by ComputerName > 3' in condition):
            print('log: count', self.file_path)
        else:
            try:
                for key, value in table.items():
                    key = key.lower()
                    if key in condition:
                        condition = condition.replace(str(key), str(value))
                return eval(condition)
            except Exception as ex:
                print('log bug condition: ', ex)

    def check(self, log):
        self.log = log
        self.rule = yaml.safe_load_all(self.raw_rule)
        detections = self.get_all_detection(self.rule)
        # todo: them nhieu detections
        selections = self.get_all_selection(detections)
        result = self.detection_operator(selections)
        return result

    def info(self):
        self.rule = yaml.safe_load_all(self.raw_rule)
        result = {}
        fields_list = ["title", "id", "description", "status", "references", "tags", "falsepositives", "level"]
        for line in self.rule:
            for key, value in line.items():
                if key in fields_list:
                    result[key] = value
        return result