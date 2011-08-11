package Postini::SAML;

use warnings;
use strict;

use Crypt::OpenSSL::RSA;
use MIME::Base64 qw( encode_base64 );
use XML::Spice;
use Date::Format qw( time2str );
use Data::Random qw( rand_chars );
use XML::CanonicalizeXML;
use Digest::SHA1 qw( sha1 );
use Carp qw( croak );

# Postini SAML ACS
my $ACS_URI = 'https://pfs.postini.com/pfs/spServlet';

sub new {
    my ($class, $arg) = @_;

    my @missing = grep { not exists $arg->{$_} } qw( keyfile certfile issuer );
    if ( @missing )
    {
        croak "missing args: " . join( q{ }, @missing );
    }
    
    my $self = bless {}, $class;

    $self->_load_rsa_key( $arg->{'keyfile'}, $arg->{'certfile'} );

    $self->{'issuer'} = $arg->{'issuer'};

    return $self;
}

sub _load_rsa_key {
    my ($self, $key_file, $cert_file) = @_;

    # load the keyfile and prepare a context for signing
    open my $key_fh, '<', $key_file or croak "couldn't open $key_file for reading: $!";
    my $key_text = do { local $/; <$key_fh> };
    close $key_fh;

    my $key = Crypt::OpenSSL::RSA->new_private_key( $key_text );
    if ( not $key )
    {
        croak "failed to instantiate Crypt::OpenSSL::RSA object from $key_file";
    }

    $key->use_pkcs1_padding();
    $self->{'key'} = $key;

    # we need to include the certificate without headers in the signed XML, so
    # extract it
    open my $cert_fh, '<', $cert_file or croak "couldn't open $cert_file for reading: $!";
    my $cert_text = do { local $/; <$cert_fh> };
    close $cert_fh;

    my ($cert_pem) = $cert_text =~ m{
        -----BEGIN\sCERTIFICATE-----
        (.+)
        -----END\sCERTIFICATE-----
    }smx;
    $cert_pem =~ s{ [\r\n]+ }{}smxg;

    # build a XML fragment containing the key info. this will be included in
    # the signature XML
    $self->{'key_info_xml'} =
        x('ds:KeyInfo',
            x('ds:X509Data',
                x('ds:X509Certificate', $cert_pem),
            ),
        ),
    ;
}

# return the current signature xml (actually XML::Spice chunk). deliberately
# returns undef if its not available, causing it to be ignored during chunk
# expansion
sub _get_cached_signature_xml {
    my ($self) = @_;
    return $self->{'signature_xml'};
}

# generate a valid, signed response and return it
sub get_response_xml {
    my ($self, $mail) = @_;

    if ( not $mail )
    {
        croak "required email address not provided";
    }

    # INPUT: 
    #   T, text-to-be-signed, a byte string; 
    #   Ks, RSA private key; 
    #
    # 1. Canonicalize the text-to-be-signed, C = C14n(T).
    # 2. Compute the message digest of the canonicalized text, m = Hash(C).
    # 3. Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
    # 4. Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
    # 5. Compose the final XML document including the signatureValue, this time in non-canonicalized form.
    
    # get rid of any cached signature
    delete $self->{'signature_xml'};

    # get the response data and canonicalise it
    my $response_xml = $self->_response_xml( $mail );
    my $canonical_response_xml = $self->_canonicalize_xml( $response_xml );

    # compute digest
    my $response_digest = encode_base64( sha1( $canonical_response_xml ), q{} );

    # create a canonical signed info fragment
    my $signed_info_xml = $self->_signed_info_xml( $response_digest );
    my $canonical_signed_info_xml = $self->_canonicalize_xml( $signed_info_xml );

    # create the signature
    my $signature = encode_base64( $self->{'key'}->sign( $canonical_signed_info_xml ), q{} );

    # now create the signature xml fragment
    $self->{'signature_xml'} = $self->_signature_xml( $signed_info_xml, $signature );;

    # force the response chunk to be regenerated which will cause the
    # signature to be included
    $response_xml->forget;

    # stringify and return
    return "".$response_xml;
}

# generate a signature XML fragment, including the signature metadata fragment
# and the raw signature
sub _signature_xml {
    my ($self, $signed_info_xml, $signature) = @_;

    my $signature_xml =
        x('ds:Signature',
            {
                'xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
            },
            $signed_info_xml,
            x('ds:SignatureValue', $signature),
            $self->{'key_info_xml'},
        ),
    ;

    return $signature_xml;
}

# generate a signature metadata XML fragement, including the message digest
sub _signed_info_xml {
    my ($self, $digest) = @_;

    my $signed_info_xml =
        x('ds:SignedInfo',
            {
                # we must include all the namespaces in use anywhere in the
                # document so they can be included in the signature
                'xmlns:ds'    => 'http://www.w3.org/2000/09/xmldsig#',
                'xmlns:saml'  => 'urn:oasis:names:tc:SAML:1.0:assertion',
                'xmlns:samlp' => 'urn:oasis:names:tc:SAML:1.0:protocol',
            },

            x('ds:CanonicalizationMethod',
                {
                    'Algorithm' => 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
                },
            ),
            x('ds:SignatureMethod',
                {
                    'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                },
            ),

            x('ds:Reference',
                {
                    'URI' => "",
                },
                x('ds:Transforms',
                    x('ds:Transform',
                        {
                            'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                        },
                    ),
                ),
                x('ds:DigestMethod',
                    {
                        'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
                    }
                ),
                x('ds:DigestValue', $digest),
            ),
        ),
    ;

    return $signed_info_xml;
}

# build the SAML response, including the signature if available
sub _response_xml {
    my ($self, $mail) = @_;

    my $now = time();
    my $issue_instant = time2str( '%Y-%m-%dT%XZ', $now, 'UTC' );

    # assertion is valid for 60 seconds
    my $not_on_or_after = time2str( '%Y-%m-%dT%XZ', $now+60, 'UTC' );

    # first character must not be a number to match xsd:ID
    my $response_id  = join q{}, 'z', rand_chars( 'set' => 'alphanumeric', 'size' => 40 );
    my $assertion_id = join q{}, 'z', rand_chars( 'set' => 'alphanumeric', 'size' => 40 );
    my $name_id      = join q{}, 'z', rand_chars( 'set' => 'alphanumeric', 'size' => 40 );

    my $response_xml =
        x('samlp:Response',
            {
                'xmlns:saml'   => 'urn:oasis:names:tc:SAML:1.0:assertion',
                'xmlns:samlp'  => 'urn:oasis:names:tc:SAML:1.0:protocol',

                'MajorVersion' => '1',
                'MinorVersion' => '1',

                'IssueInstant' => $issue_instant,
                'ResponseID'   => $response_id,
                'Recipient'    => $ACS_URI,
            },

            # include the signature if its available. if not then it wil be
            # undef and will be ignored
            sub { $self->{'signature_xml'} },

            x('samlp:Status',
                x('samlp:StatusCode',
                    {
                        'Value' => 'samlp:Success',
                    },
                ),
            ),

            x('saml:Assertion',
                {
                    'MajorVersion' => '1',
                    'MinorVersion' => '1',

                    'IssueInstant' => $issue_instant,
                    'AssertionID'  => $assertion_id,
                    'Issuer'       => $self->{'issuer'},
                },

                x('saml:Conditions',
                    {
                        'NotBefore'    => $issue_instant,
                        'NotOnOrAfter' => $not_on_or_after,
                    },
                ),

                x('saml:AuthenticationStatement',
                    {
                        'AuthenticationInstant' => $issue_instant,
                        'AuthenticationMethod' => 'urn:oasis:names:tc:SAML:1.0:am:unspecified',
                    },

                    x('saml:Subject',
                        x('saml:NameIdentifier', $name_id),
                        x('saml:SubjectConfirmation',
                            x('saml:ConfirmationMethod', 'urn:oasis:names:tc:SAML:1.0:cm:bearer'),
                        ),
                    ),
                ),

                x('saml:AttributeStatement',
                    x('saml:Subject',
                        x('saml:NameIdentifier', $name_id),
                        x('saml:SubjectConfirmation',
                            x('saml:ConfirmationMethod', 'urn:oasis:names:tc:SAML:1.0:cm:bearer'),
                        ),
                    ),

                    x('saml:Attribute',
                        {
                            'AttributeName'      => 'personal_email',
                            'AttributeNamespace' => 'urn:mace:shibboleth:1.0:attributeNamespace:uri',
                        },
                        x('saml:AttributeValue', $mail),
                    ),
                ),
            ),
        ),
    ;

    return $response_xml;
}

# canonicalise XML using W3C REC-xml-c14n-20010315 algorithm
# returns a string, not a XML::Spice chunk
sub _canonicalize_xml {
    my ($self, $xml) = @_;

    my $xpath = '<XPath>(//. | //@* | //namespace::*)</XPath>';
    return XML::CanonicalizeXML::canonicalize( $xml, $xpath, [], 0, 0 );
}

sub get_form {
    my ($self, $mail) = @_;

    my $saml_response = encode_base64( $self->get_response_xml( $mail ), q{} );

    my $html = join( q{},
        qq{<form action="$ACS_URI" method="post">},
        qq{<input type="hidden" name="SAMLResponse" value="$saml_response" />},
        qq{<input type="hidden" name="TARGET" value="$ACS_URI" />},
        qq{<input type="submit" name="Submit" value="Submit" />},
        qq{</form>},
    );

    return $html;
}

__END__

=head1 NAME

Postini::SAML - Do SAML login to Google Postini services

=cut

1;
