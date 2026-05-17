// ©AngelaMos | 2026
// service_test.go

package geoip

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/stretchr/testify/require"
)

type fakeCityReader struct {
	rec        *geoip2.City
	err        error
	calls      int
	closeCalls int
	closeErr   error
}

func (f *fakeCityReader) City(netip.Addr) (*geoip2.City, error) {
	f.calls++
	return f.rec, f.err
}

func (f *fakeCityReader) Close() error {
	f.closeCalls++
	return f.closeErr
}

func newServiceWithFake(r *fakeCityReader) *Service {
	return &Service{reader: r}
}

func TestNopService_AlwaysReturnsEmpty(t *testing.T) {
	t.Parallel()
	n := NopService()
	require.Equal(t, Lookup{}, n.Lookup("203.0.113.1"))
	require.Equal(t, Lookup{}, n.Lookup(""))
	require.Equal(t, Lookup{}, n.Lookup("not-an-ip"))
}

func TestNopService_SatisfiesLookuper(t *testing.T) {
	t.Parallel()
	var _ Lookuper = NopService()
}

func TestServiceImplementsLookuper(t *testing.T) {
	t.Parallel()
	var _ Lookuper = (*Service)(nil)
}

func TestOpen_EmptyPathReturnsError(t *testing.T) {
	t.Parallel()
	s, err := Open("")
	require.Error(t, err)
	require.Nil(t, s)
}

func TestOpen_NonexistentPathReturnsError(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nonexistent.mmdb")
	s, err := Open(missing)
	require.Error(t, err)
	require.Nil(t, s)
}

func TestService_Lookup_NilReceiverReturnsEmpty(t *testing.T) {
	t.Parallel()
	var s *Service
	require.Equal(t, Lookup{}, s.Lookup("203.0.113.1"))
}

func TestService_Lookup_NilReaderReturnsEmpty(t *testing.T) {
	t.Parallel()
	s := &Service{}
	require.Equal(t, Lookup{}, s.Lookup("203.0.113.1"))
}

func TestService_Lookup_EmptyIPReturnsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{}
	s := newServiceWithFake(fake)
	require.Equal(t, Lookup{}, s.Lookup(""))
	require.Equal(t, 0, fake.calls,
		"empty IP must short-circuit before reader call")
}

func TestService_Lookup_MalformedIPReturnsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{}
	s := newServiceWithFake(fake)
	for _, bad := range []string{"not-an-ip", "999.999.999.999", "::xyz", " "} {
		require.Equal(t, Lookup{}, s.Lookup(bad), "input=%q", bad)
	}
	require.Equal(t, 0, fake.calls,
		"malformed IP must short-circuit before reader call")
}

func TestService_Lookup_ReaderErrorReturnsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{err: errors.New("boom")}
	s := newServiceWithFake(fake)
	require.Equal(t, Lookup{}, s.Lookup("203.0.113.1"))
	require.Equal(t, 1, fake.calls)
}

func TestService_Lookup_NoDataReturnsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{rec: &geoip2.City{}}
	s := newServiceWithFake(fake)
	require.Equal(t, Lookup{}, s.Lookup("203.0.113.1"))
}

func TestService_Lookup_NilRecordReturnsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{rec: nil}
	s := newServiceWithFake(fake)
	require.Equal(t, Lookup{}, s.Lookup("203.0.113.1"))
}

func TestService_Lookup_PopulatesAllAvailableFields(t *testing.T) {
	t.Parallel()
	rec := &geoip2.City{}
	rec.Country.ISOCode = "US"
	rec.Country.Names.English = "United States"
	rec.City.Names.English = "Mountain View"
	rec.Subdivisions = []geoip2.CitySubdivision{
		{Names: geoip2.Names{English: "California"}, ISOCode: "CA"},
	}
	fake := &fakeCityReader{rec: rec}
	s := newServiceWithFake(fake)

	got := s.Lookup("203.0.113.1")
	require.Equal(t, "US", got.Country)
	require.Equal(t, "California", got.Region)
	require.Equal(t, "Mountain View", got.City)
	require.Equal(t, 0, got.ASN,
		"City db carries no ASN; field is reserved for ASN-db extension")
	require.Empty(t, got.ASNOrg,
		"City db carries no ASNOrg; field is reserved for ASN-db extension")
}

func TestService_Lookup_AcceptsIPv6(t *testing.T) {
	t.Parallel()
	rec := &geoip2.City{}
	rec.Country.ISOCode = "DE"
	rec.City.Names.English = "Berlin"
	fake := &fakeCityReader{rec: rec}
	s := newServiceWithFake(fake)

	got := s.Lookup("2001:db8::1")
	require.Equal(t, "DE", got.Country)
	require.Equal(t, "Berlin", got.City)
}

func TestExtractLookup_NilReturnsEmpty(t *testing.T) {
	t.Parallel()
	require.Equal(t, Lookup{}, extractLookup(nil))
}

func TestExtractLookup_PicksFirstSubdivisionEnglishName(t *testing.T) {
	t.Parallel()
	rec := &geoip2.City{}
	rec.Subdivisions = []geoip2.CitySubdivision{
		{Names: geoip2.Names{English: "England"}, ISOCode: "ENG"},
		{Names: geoip2.Names{English: "Oxfordshire"}, ISOCode: "OXF"},
	}
	require.Equal(t, "England", extractLookup(rec).Region)
}

func TestExtractLookup_FallsBackToISOCodeWhenEnglishMissing(t *testing.T) {
	t.Parallel()
	rec := &geoip2.City{}
	rec.Subdivisions = []geoip2.CitySubdivision{
		{ISOCode: "CA"},
	}
	require.Equal(t, "CA", extractLookup(rec).Region)
}

func TestExtractLookup_NoSubdivisionsLeavesRegionEmpty(t *testing.T) {
	t.Parallel()
	rec := &geoip2.City{}
	rec.Country.ISOCode = "JP"
	got := extractLookup(rec)
	require.Empty(t, got.Region)
	require.Equal(t, "JP", got.Country)
}

func TestService_Close_NilReceiverIsNoOp(t *testing.T) {
	t.Parallel()
	var s *Service
	require.NoError(t, s.Close())
}

func TestService_Close_NilReaderIsNoOp(t *testing.T) {
	t.Parallel()
	require.NoError(t, (&Service{}).Close())
}

func TestService_Close_DelegatesToReader(t *testing.T) {
	t.Parallel()
	fake := &fakeCityReader{}
	require.NoError(t, newServiceWithFake(fake).Close())
	require.Equal(t, 1, fake.closeCalls)
}

func TestService_Close_PropagatesReaderError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("close failed")
	fake := &fakeCityReader{closeErr: wantErr}
	require.ErrorIs(t, newServiceWithFake(fake).Close(), wantErr)
}

func TestFirstSubdivisionName_EmptySliceReturnsEmpty(t *testing.T) {
	t.Parallel()
	require.Empty(t, firstSubdivisionName(nil))
	require.Empty(t, firstSubdivisionName([]geoip2.CitySubdivision{}))
}

func TestFirstSubdivisionName_PrefersEnglishName(t *testing.T) {
	t.Parallel()
	subs := []geoip2.CitySubdivision{{
		Names:   geoip2.Names{English: "California"},
		ISOCode: "CA",
	}}
	require.Equal(t, "California", firstSubdivisionName(subs))
}

func TestFirstSubdivisionName_FallsBackToISOCode(t *testing.T) {
	t.Parallel()
	subs := []geoip2.CitySubdivision{{ISOCode: "CA"}}
	require.Equal(t, "CA", firstSubdivisionName(subs))
}

func TestFirstSubdivisionName_SkipsEntirelyEmptyEntries(t *testing.T) {
	t.Parallel()
	subs := []geoip2.CitySubdivision{
		{},
		{Names: geoip2.Names{English: "Oxfordshire"}},
	}
	require.Equal(t, "Oxfordshire", firstSubdivisionName(subs))
}

func TestFirstSubdivisionName_AllEmptyEntriesReturnsEmpty(t *testing.T) {
	t.Parallel()
	subs := []geoip2.CitySubdivision{{}, {}, {}}
	require.Empty(t, firstSubdivisionName(subs))
}
