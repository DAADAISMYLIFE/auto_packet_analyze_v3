# 모든 파일에 md5/sha1/sha256 해시 애널라이저를 명시적으로 붙인다.
# native zeek 8.x 에서 policy/frameworks/files/hash-all-files 가 sha256 을
# 켜지 않는 문제(md5 만 나옴)를 우회 — 세 해시 모두 강제한다.
@load base/files/hash

event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA1);
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }
