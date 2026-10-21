import time
import unittest

from gesher import client


class FakeResponse:
    def __init__(self, chunks):
        self.chunks = chunks
        self.requested_size = None

    def iter_content(self, chunk_size=1):
        self.requested_size = chunk_size
        yield from self.chunks


def lines_of(chunks):
    return list(client.iter_stream_lines(FakeResponse(chunks)))


class TestStreamLines(unittest.TestCase):
    def test_lines_split_across_chunks_are_joined(self):
        self.assertEqual(
            lines_of([b'{"a":', b"1}\n{", b'"b":2}\n']),
            [b'{"a":1}', b'{"b":2}'],
        )

    def test_several_lines_in_one_chunk(self):
        self.assertEqual(lines_of([b"a\nb\nc\n"]), [b"a", b"b", b"c"])

    def test_empty_lines_are_skipped(self):
        self.assertEqual(lines_of([b"\n\na\n\nb\n"]), [b"a", b"b"])

    def test_last_line_without_a_newline_is_delivered(self):
        self.assertEqual(lines_of([b"a\nlast"]), [b"a", b"last"])

    def test_a_line_is_delivered_as_soon_as_its_chunk_arrives(self):
        produced = []

        def chunks():
            produced.append("first")
            yield b"one\n"
            produced.append("second")
            yield b"two\n"

        response = FakeResponse([])
        response.iter_content = lambda chunk_size=1: chunks()
        stream = client.iter_stream_lines(response)
        self.assertEqual(next(stream), b"one")
        self.assertEqual(produced, ["first"])

    def test_reads_in_large_blocks(self):
        response = FakeResponse([b"a\n"])
        list(client.iter_stream_lines(response))
        self.assertEqual(response.requested_size, client.STREAM_READ_SIZE)
        self.assertGreaterEqual(client.STREAM_READ_SIZE, 4096)

    def test_a_multi_megabyte_line_is_read_in_linear_time(self):
        line = b"x" * 3_000_000 + b"\n"
        chunks = [line[i : i + 512] for i in range(0, len(line), 512)]
        started = time.monotonic()
        result = lines_of(chunks)
        elapsed = time.monotonic() - started
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]), 3_000_000)
        self.assertLess(elapsed, 3.0)


if __name__ == "__main__":
    unittest.main()
