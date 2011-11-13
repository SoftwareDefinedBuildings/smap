
import os

from zope.interface import implements
from twisted.internet import defer, protocol, task, reactor
from twisted.web.iweb import UNKNOWN_LENGTH, IBodyProducer

# Backport of
# svn://svn.twistedmatrix.com/svn/Twisted/trunk@32157 bbbe8e31-12d6-0310-92fd-ac37d47ddeeb
# 
class FileBodyProducer(object):
    """
    L{FileBodyProducer} produces bytes from an input file object incrementally
    and writes them to a consumer.

    Since file-like objects cannot be read from in an event-driven manner,
    L{FileBodyProducer} uses a L{Cooperator} instance to schedule reads from
    the file.  This process is also paused and resumed based on notifications
    from the L{IConsumer} provider being written to.

    The file is closed after it has been read, or if the producer is stopped
    early.

    @ivar _inputFile: Any file-like object, bytes read from which will be
        written to a consumer.

    @ivar _cooperate: A method like L{Cooperator.cooperate} which is used to
        schedule all reads.

    @ivar _readSize: The number of bytes to read from C{_inputFile} at a time.
    """
    implements(IBodyProducer)

    def __init__(self, inputFile, cooperator=task, readSize=2 ** 16):
        self._inputFile = inputFile
        self._cooperate = cooperator.cooperate
        self._readSize = readSize
        self.length = self._determineLength(inputFile)

    def _determineLength(self, fObj):
        """
        Determine how many bytes can be read out of C{fObj} (assuming it is not
        modified from this point on).  If the determination cannot be made,
        return C{UNKNOWN_LENGTH}.
        """
        try:
            seek = fObj.seek
            tell = fObj.tell
        except AttributeError:
            return UNKNOWN_LENGTH
        originalPosition = tell()
        seek(0, os.SEEK_END)
        end = tell()
        seek(originalPosition, os.SEEK_SET)
        return end - originalPosition

    def stopProducing(self):
        """
        Permanently stop writing bytes from the file to the consumer by
        stopping the underlying L{CooperativeTask}.
        """
        self._inputFile.close()
        self._task.stop()

    def startProducing(self, consumer):
        """
        Start a cooperative task which will read bytes from the input file and
        write them to C{consumer}.  Return a L{Deferred} which fires after all
        bytes have been written.

        @param consumer: Any L{IConsumer} provider
        """
        self._task = self._cooperate(self._writeloop(consumer))
        d = self._task.whenDone()
        def maybeStopped(reason):
            # IBodyProducer.startProducing's Deferred isn't support to fire if
            # stopProducing is called.
            reason.trap(task.TaskStopped)
            return defer.Deferred()
        d.addCallbacks(lambda ignored: None, maybeStopped)
        return d

    def _writeloop(self, consumer):
        """
        Return an iterator which reads one chunk of bytes from the input file
        and writes them to the consumer for each time it is iterated.
        """
        while True:
            bytes = self._inputFile.read(self._readSize)
            if not bytes:
                self._inputFile.close()
                break
            consumer.write(bytes)
            yield None

    def pauseProducing(self):
        """
        Temporarily suspend copying bytes from the input file to the consumer
        by pausing the L{CooperativeTask} which drives that activity.
        """
        self._task.pause()

    def resumeProducing(self):
        """
        Undo the effects of a previous C{pauseProducing} and resume copying
        bytes to the consumer by resuming the L{CooperativeTask} which drives
        the write activity.
        """
        self._task.resume()
