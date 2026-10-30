"""Refresh and verify the homepage derivatives of the recorded hero GIF."""

import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from fractions import Fraction


def probe(path):
    data = json.loads(subprocess.check_output([
        "ffprobe", "-v", "error", "-show_streams", "-show_frames",
        "-show_format", "-of", "json", str(path),
    ]))
    if len(data.get("streams", [])) != 1 or not data.get("frames"):
        raise ValueError(f"{path}: expected one complete video stream")
    return data


def timeline(data):
    return [(Fraction(f["pts_time"]), Fraction(
        f.get("duration_time") or f["pkt_duration_time"]
    )) for f in data["frames"]]


def frame_hashes(path):
    # Decode every frame, including data beyond what container headers claim.
    output = subprocess.check_output([
        "ffmpeg", "-v", "error", "-xerror", "-err_detect", "explode",
        "-i", str(path), "-an", "-pix_fmt", "rgb24",
        "-fps_mode", "passthrough", "-f", "framemd5", "-",
    ], text=True)
    return [line.rsplit(",", 1)[1].strip() for line in output.splitlines()
            if line and not line.startswith("#")]


def verify(gif, video, poster):
    source, movie, still = (probe(p) for p in (gif, video, poster))
    src, dst, png = (p["streams"][0] for p in (source, movie, still))
    if src["codec_name"] != "gif" or dst["codec_name"] != "h264" or png["codec_name"] != "png":
        raise ValueError("expected GIF, H.264 and PNG codecs")
    if source["format"]["format_name"] != "gif" or still["format"]["format_name"] != "png_pipe":
        raise ValueError("expected GIF and PNG containers")
    if "mp4" not in movie["format"]["format_name"].split(","):
        raise ValueError("expected an MP4 container")
    if dst["pix_fmt"] != "yuv420p" or dst["profile"] not in ("Baseline", "Constrained Baseline"):
        raise ValueError("expected browser-compatible baseline H.264 in yuv420p")
    for stream in (dst, png):
        if (stream["width"], stream["height"]) != (src["width"], src["height"]):
            raise ValueError("media dimensions changed")
    times = timeline(source)
    if times[0][0] != 0 or any(duration <= 0 for _, duration in times):
        raise ValueError("invalid GIF timing")
    if timeline(movie) != times:
        raise ValueError("MP4 frame coverage or timing changed")
    end = times[-1][0] + times[-1][1]
    if any(Fraction(p["format"]["duration"]) != end for p in (source, movie)):
        raise ValueError("media duration changed")
    original, encoded, final = (frame_hashes(p) for p in (gif, video, poster))
    if len(original) != len(times) or len(encoded) != len(times):
        raise ValueError("incomplete decoded frame coverage")
    if len(still["frames"]) != 1 or final != [original[-1]]:
        raise ValueError("poster is not the GIF's final frame")
    data = video.read_bytes()
    atoms = []
    offset = 0
    while offset < len(data):
        size, kind = struct.unpack(">I4s", data[offset:offset + 8])
        if size < 8 or offset + size > len(data):
            raise ValueError("invalid MP4 atom")
        atoms.append(kind)
        offset += size
    if b"moov" not in atoms or b"mdat" not in atoms or atoms.index(b"moov") > atoms.index(b"mdat"):
        raise ValueError("MP4 lacks faststart")


def refresh(assets):
    gif = assets / "hero.gif"
    count = len(probe(gif)["frames"])
    with tempfile.TemporaryDirectory(prefix=".demo-media-", dir=assets) as directory:
        video = Path(directory) / "hero.mp4"
        poster = Path(directory) / "hero-poster.png"
        subprocess.check_call([
            "ffmpeg", "-v", "error", "-xerror", "-i", str(gif), "-an",
            "-c:v", "libx264", "-preset", "slow", "-crf", "21",
            "-profile:v", "baseline", "-level:v", "3.1", "-pix_fmt", "yuv420p",
            "-fps_mode", "passthrough", "-enc_time_base", "1:100",
            "-video_track_timescale", "100", "-movflags", "+faststart", str(video),
        ])
        subprocess.check_call([
            "ffmpeg", "-v", "error", "-xerror", "-i", str(gif),
            "-vf", f"select=eq(n\\,{count - 1})", "-frames:v", "1",
            "-pix_fmt", "rgb24", "-compression_level", "9", "-update", "1", str(poster),
        ])
        verify(gif, video, poster)
        os.replace(video, assets / video.name)
        os.replace(poster, assets / poster.name)
    print(f"Verified GIF, MP4 and final-frame poster: {count} frames")


if __name__ == "__main__":
    refresh(Path("assets"))
