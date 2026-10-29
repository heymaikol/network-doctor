"""Offline checks for demo validation and publication failure paths."""

import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import demo_media


class DemoMediaTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.assets = Path(self.directory.name)
        self.gif, self.video, self.poster = (
            self.assets / name for name in ("hero.gif", "hero.mp4", "hero-poster.png")
        )
        self.video.write_bytes(struct.pack(">I4sI4s", 8, b"moov", 8, b"mdat"))
        frames = [{"pts_time": "0", "duration_time": "0.04"},
                  {"pts_time": "0.04", "duration_time": "0.12"}]
        self.source = {"streams": [{"codec_name": "gif", "width": 32, "height": 24}],
                       "frames": frames, "format": {"format_name": "gif", "duration": "0.16"}}
        self.movie = copy.deepcopy(self.source)
        self.movie["streams"][0].update(codec_name="h264", pix_fmt="yuv420p", profile="Baseline")
        self.movie["format"]["format_name"] = "mov,mp4,m4a,3gp,3g2,mj2"
        self.still = copy.deepcopy(self.source)
        self.still["streams"][0]["codec_name"] = "png"
        self.still["frames"] = frames[:1]
        self.still["format"]["format_name"] = "png_pipe"
        self.hashes = [["first", "final"], ["encoded-first", "encoded-final"], ["final"]]

    def verify(self):
        with patch.object(demo_media, "probe", side_effect=[self.source, self.movie, self.still]), \
             patch.object(demo_media, "frame_hashes", side_effect=self.hashes):
            demo_media.verify(self.gif, self.video, self.poster)

    def test_accepts_complete_variable_frame_timing(self):
        self.verify()

    def test_probe_rejects_missing_frames_or_additional_streams(self):
        for data in [{"streams": [], "frames": []},
                     {"streams": [{}], "frames": []},
                     {"streams": [{}, {}], "frames": [{}]}]:
            with self.subTest(data=data), \
                 patch.object(demo_media.subprocess, "check_output", return_value=json.dumps(data)):
                with self.assertRaises(ValueError):
                    demo_media.probe(self.gif)

    def test_rejects_wrong_image_containers(self):
        for data in [self.source, self.still]:
            previous = data["format"]["format_name"]
            data["format"]["format_name"] = "avi"
            with self.assertRaises(ValueError):
                self.verify()
            data["format"]["format_name"] = previous

    def test_rejects_incomplete_or_changed_media(self):
        for target, key, value in [
            ("frames", "frames", self.movie["frames"][:1]),
            ("time", "pts_time", "0.05"),
            ("time", "duration_time", "0.13"),
            ("format", "duration", "0.17"),
            ("format", "format_name", "avi"),
            ("stream", "width", 30),
            ("stream", "height", 22),
            ("stream", "codec_name", "mpeg4"),
            ("stream", "pix_fmt", "yuv444p"),
            ("stream", "profile", "High"),
        ]:
            with self.subTest(target=target, key=key):
                original = copy.deepcopy(self.movie)
                section = {"frames": self.movie, "time": self.movie["frames"][-1],
                           "format": self.movie["format"], "stream": self.movie["streams"][0]}[target]
                section[key] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.movie = original

    def test_rejects_incomplete_decode_or_wrong_final_frame(self):
        for hashes in [
            [["first"], ["a", "b"], ["first"]],
            [["first", "final"], ["a"], ["final"]],
            [["first", "final"], ["a", "b"], ["first"]],
        ]:
            with self.subTest(hashes=hashes):
                self.hashes = hashes
                with self.assertRaises(ValueError):
                    self.verify()

    def test_rejects_wrong_poster_dimensions_or_codec(self):
        for key, value in [("width", 30), ("codec_name", "mjpeg")]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.still)
                self.still["streams"][0][key] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.still = original

    def test_rejects_missing_faststart_or_malformed_atoms(self):
        for data in [struct.pack(">I4sI4s", 8, b"mdat", 8, b"moov"),
                     struct.pack(">I4s", 0, b"moov"),
                     struct.pack(">I4s", 99, b"moov")]:
            with self.subTest(data=data):
                self.video.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_conversion_and_validation_failures_preserve_derivatives(self):
        self.gif.write_bytes(b"recording")
        self.video.write_bytes(b"old video")
        self.poster.write_bytes(b"old poster")
        for conversion_fails in (True, False):
            with self.subTest(conversion_fails=conversion_fails):
                def convert(command):
                    Path(command[-1]).write_bytes(b"partial or invalid output")
                    if conversion_fails:
                        raise subprocess.CalledProcessError(1, command)

                with patch.object(demo_media, "probe", return_value=self.source), \
                     patch.object(demo_media.subprocess, "check_call", side_effect=convert), \
                     patch.object(demo_media, "verify", side_effect=ValueError("invalid media")):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        demo_media.refresh(self.assets)
                self.assertEqual(self.video.read_bytes(), b"old video")
                self.assertEqual(self.poster.read_bytes(), b"old poster")
                self.assertEqual(sorted(p.name for p in self.assets.iterdir()),
                                 ["hero-poster.png", "hero.gif", "hero.mp4"])


if __name__ == "__main__":
    unittest.main()
