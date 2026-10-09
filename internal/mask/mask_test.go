package mask

import "testing"

func TestSecret(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"short":                                "****",
		"874a3175-290a-4849-8329-5ae17d58f5aa": "874a…f5aa",
		"0123456789abcdef0123456789abcdef01234567": "0123…4567",
	}
	for in, want := range cases {
		if got := Secret(in); got != want {
			t.Errorf("Secret(%q)=%q want %q", in, got, want)
		}
	}
}
