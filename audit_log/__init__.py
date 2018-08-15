VERSION = (0, 11, 2, 'beta'
                     '')

if VERSION[-1] != "final":  # pragma: no cover
    __version__ = '.'.join(map(str, VERSION))
else:  # pragma: no cover
    __version__ = '.'.join(map(str, VERSION[:-1]))
