class KeyParityWarning(Warning):
    pass


class WithdrawnWarning(Warning):
    pass


class DeprecatedWarning(Warning):
    pass


class DisallowedWarning(Warning):
    pass


class PointAtInfinity(Exception):
    def __init__(self, operation):
        super(PointAtInfinity, self).__init__(f'{operation} results in point at infinity')


class InvalidComparison(Exception):
    def __init__(self, operand1, operand2):
        super(InvalidComparison, self).__init__(f'Invalid comparison between {type(operand1)} and {type(operand2)}')
