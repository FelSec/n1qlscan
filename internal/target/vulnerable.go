package target

import (
	"fmt"
	"strconv"
	"strings"
)

type VulnLocation int

const (
	VQUERY VulnLocation = iota
	VBODY
	VPATH
	VHEADER
	VCOOKIE
)

var vulnLocationName = map[VulnLocation]string{
	VQUERY:  "Query parameter",
	VBODY:   "Body parameter",
	VPATH:   "Path segment",
	VHEADER: "Header",
	VCOOKIE: "Cookie",
}

func (vl VulnLocation) String() string {
	return vulnLocationName[vl]
}

type ExploitType int

const (
	BOOLBLIND ExploitType = iota
	UNION
	STACK
	STRCONCAT
	ERROR
	UNKOWN
)

var exploitTypeName = map[ExploitType]string{
	BOOLBLIND: "Boolean-based Blind",
	UNION:     "Union-based",
	STACK:     "Stacked Query",
	STRCONCAT: "String Concatenation",
	ERROR:     "Error-based",
	UNKOWN:    "Unknown",
}

func (et ExploitType) String() string {
	return exploitTypeName[et]
}

type Vulnerable struct {
	Location        VulnLocation
	ExploitType     ExploitType
	Parameter       string
	BasePayload     string
	DetectPayload   string
	ExamplePayload  string
	Detection       int
	PayloadTemplate string
}

func (v Vulnerable) String() string {
	return fmt.Sprintf(
		"%s %s is vulnerable to %s N1QL injection\nLocation: %s\nParameter: %s\nDetection Method: %s\nExploit Type: %s\nExample Payload: %s\nPayload Template: %s\n",
		v.Location,
		v.Parameter,
		v.ExploitType,
		v.Location,
		v.Parameter,
		v.DetectPayload,
		v.ExploitType,
		v.ExamplePayload,
		v.PayloadTemplate)
}

func (v Vulnerable) VerboseString() string {
	return fmt.Sprintf(
		"Location: %s\nParameter: %s\nDetection Method: %s\nExploit Type: %s\nExample Payload: %s\nPayload Template: %s",
		v.Location,
		v.Parameter,
		v.DetectPayload,
		v.ExploitType,
		v.ExamplePayload,
		v.PayloadTemplate)
}

func (v Vulnerable) Serialize() string {
	return strings.ReplaceAll(
		fmt.Sprintf("L%d¬X%d¬P%s¬B%s¬D%s¬E%s¬T%s¬F%d\n",
			v.Location,
			v.ExploitType,
			v.Parameter,
			v.BasePayload,
			v.DetectPayload,
			v.ExamplePayload,
			v.PayloadTemplate,
			v.Detection), " ", "~")
}

func Deserialize(data string) (int, Vulnerable) {
	data = strings.ReplaceAll(data, "~", " ")
	index := data[0:strings.Index(data, ":")]
	indexValue, _ := strconv.Atoi(index)
	data = strings.Replace(data, index+":", "", 1)
	sections := strings.Split(data, "¬")
	location, err := strconv.Atoi(sections[0][1:])
	if err != nil {
		fmt.Printf("Unable to convert %s\n", sections[0][1:])
		return 0, Vulnerable{}
	}
	if location > 4 || location < 0 {
		fmt.Printf("Unsupported location value\n")
		return 0, Vulnerable{}
	}
	exploitType, err := strconv.Atoi(sections[1][1:])
	if err != nil {
		fmt.Printf("Unable to convert %s\n", sections[1][1:])
		return 0, Vulnerable{}
	}
	if exploitType > 5 || exploitType < 0 {
		fmt.Printf("Unsupported exploit type value\n")
		return 0, Vulnerable{}
	}
	parameter := sections[2][1:]
	basePayload := sections[3][1:]
	detectPayload := sections[4][1:]
	examplePayload := sections[5][1:]
	payloadTemplate := sections[6][1:]
	detection, err := strconv.Atoi(sections[7][1:])
	if err != nil {
		fmt.Printf("Unable to convert %s\n", sections[7][1:])
		return 0, Vulnerable{}
	}
	if detection > 12 || detection < 0 {
		fmt.Printf("Unsupported detection value\n")
		return 0, Vulnerable{}
	}

	return indexValue, Vulnerable{Location: VulnLocation(location), ExploitType: ExploitType(exploitType), Parameter: parameter, BasePayload: basePayload, DetectPayload: detectPayload, ExamplePayload: examplePayload, PayloadTemplate: payloadTemplate, Detection: detection}
}
