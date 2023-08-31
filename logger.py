from datetime import datetime

class Log:
    def __init__(self, path, uniq=False):
        current_time = datetime.now().strftime("%m%d%H%M%S")
        if uniq:
            self.__fname = f'{path}/debug-{current_time}.log'
        else:
            self.__fname = f'{path}/debug.log'
        self.entry("--------> Beginning run", 'DEBUG')

    def entry(self, message, level='OUT'):
        current_time = datetime.now().strftime("%m/%d %H:%M:%S")
        entry = f'[{current_time}][{level}]: {message}\n'
        if level != 'DEBUG':
            print(message)
        with open(self.__fname, 'a') as f:
            f.writelines(entry)
