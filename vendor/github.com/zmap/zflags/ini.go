package flags

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// IniError contains location information on where an error occurred.
type IniError struct {
	// The error message.
	Message string

	// The filename of the file in which the error occurred.
	File string

	// The line number at which the error occurred.
	LineNumber uint
}

// Error provides a "file:line: message" formatted message of the ini error.
func (x *IniError) Error() string {
	return fmt.Sprintf(
		"%s:%d: %s",
		x.File,
		x.LineNumber,
		x.Message,
	)
}

// IniOptions for writing
type IniOptions uint

const (
	// IniNone indicates no options.
	IniNone IniOptions = 0

	// IniIncludeDefaults indicates that default values should be written.
	IniIncludeDefaults = 1 << iota

	// IniCommentDefaults indicates that if IniIncludeDefaults is used
	// options with default values are written but commented out.
	IniCommentDefaults

	// IniIncludeComments indicates that comments containing the description
	// of an option should be written.
	IniIncludeComments

	// IniDefault provides a default set of options.
	IniDefault = IniIncludeComments
)

// IniParser is a utility to read and write flags options from and to ini
// formatted strings.
type IniParser struct {
	ParseAsDefaults bool // override default flags

	parser *Parser
}

type iniValue struct {
	Name       string
	Value      string
	Quoted     bool
	LineNumber uint
}

type iniSection []iniValue

type ini struct {
	File     string
	Sections map[string]iniSection
}

// NewIniParser creates a new ini parser for a given Parser.
func NewIniParser(p *Parser) *IniParser {
	return &IniParser{
		parser: p,
	}
}

// IniParse is a convenience function to parse command line options with default
// settings from an ini formatted file. The provided data is a pointer to a struct
// representing the default option group (named "Application Options"). For
// more control, use flags.NewParser.
func IniParse(filename string, data interface{}) ([]string, []interface{}, error) {
	p := NewParser(data, Default)

	return NewIniParser(p).ParseFile(filename)
}

// ParseFile parses flags from an ini formatted file. See Parse for more
// information on the ini file format. The returned errors can be of the type
// flags.Error or flags.IniError.
func (i *IniParser) ParseFile(filename string) ([]string, []interface{}, error) {
	ini, err := readIniFromFile(filename)

	if err != nil {
		return nil, nil, err
	}

	return i.parse(ini)
}

// Parse parses flags from an ini format. You can use ParseFile as a
// convenience function to parse from a filename instead of a general
// io.Reader.
//
// The format of the ini file is as follows:
//
//     [Option group name]
//     option = value
//
// Each section in the ini file represents an option group or command in the
// flags parser. The default flags parser option group (i.e. when using
// flags.Parse) is named 'Application Options'. The ini option name is matched
// in the following order:
//
//     1. Compared to the ini-name tag on the option struct field (if present)
//     2. Compared to the struct field name
//     3. Compared to the option long name (if present)
//     4. Compared to the option short name (if present)
//
// Sections for nested groups and commands can be addressed using a dot `.'
// namespacing notation (i.e [subcommand.Options]). Group section names are
// matched case insensitive.
//
// The returned errors can be of the type flags.Error or flags.IniError.
func (i *IniParser) Parse(reader io.Reader) ([]string, []interface{}, error) {
	ini, err := readIni(reader, "")

	if err != nil {
		return nil, nil, err
	}

	return i.parse(ini)
}

// WriteFile writes the flags as ini format into a file. See Write
// for more information. The returned error occurs when the specified file
// could not be opened for writing.
func (i *IniParser) WriteFile(filename string, options IniOptions) error {
	return writeIniToFile(i, filename, options)
}

// Write writes the current values of all the flags to an ini format.
// See Parse for more information on the ini file format. You typically
// call this only after settings have been parsed since the default values of each
// option are stored just before parsing the flags (this is only relevant when
// IniIncludeDefaults is _not_ set in options).
func (i *IniParser) Write(writer io.Writer, options IniOptions) {
	writeIni(i, writer, options)
}

func readFullLine(reader *bufio.Reader) (string, error) {
	var line []byte

	for {
		l, more, err := reader.ReadLine()

		if err != nil {
			return "", err
		}

		if line == nil && !more {
			return string(l), nil
		}

		line = append(line, l...)

		if !more {
			break
		}
	}

	return string(line), nil
}

func optionIniName(option *Option) string {
	name := option.tag.Get("_read-ini-name")

	if len(name) != 0 {
		return name
	}

	name = option.tag.Get("ini-name")

	if len(name) != 0 {
		return name
	}

	return option.field.Name
}

func writeGroupIni(cmd *Command, group *Group, namespace string, writer io.Writer, options IniOptions) {
	var sname string

	if len(namespace) != 0 {
		sname = namespace
	}

	if cmd.Group != group && len(group.ShortDescription) != 0 {
		if len(sname) != 0 {
			sname += "."
		}

		sname += group.ShortDescription
	}

	sectionwritten := false
	comments := (options & IniIncludeComments) != IniNone

	for _, option := range group.options {
		if option.isFunc() || option.Hidden {
			continue
		}

		if len(option.tag.Get("no-ini")) != 0 {
			continue
		}

		val := option.value

		if (options&IniIncludeDefaults) == IniNone && option.valueIsDefault() {
			continue
		}

		if !sectionwritten {
			fmt.Fprintf(writer, "[%s]\n", sname)
			sectionwritten = true
		}

		if comments && len(option.Description) != 0 {
			fmt.Fprintf(writer, "; %s\n", option.Description)
		}

		oname := optionIniName(option)

		commentOption := (options&(IniIncludeDefaults|IniCommentDefaults)) == IniIncludeDefaults|IniCommentDefaults && option.valueIsDefault()

		kind := val.Type().Kind()
		switch kind {
		case reflect.Slice:
			kind = val.Type().Elem().Kind()

			if val.Len() == 0 {
				writeOption(writer, oname, kind, "", "", true, option.iniQuote)
			} else {
				for idx := 0; idx < val.Len(); idx++ {
					v, _ := convertToString(val.Index(idx), option.tag)

					writeOption(writer, oname, kind, "", v, commentOption, option.iniQuote)
				}
			}
		case reflect.Map:
			kind = val.Type().Elem().Kind()

			if val.Len() == 0 {
				writeOption(writer, oname, kind, "", "", true, option.iniQuote)
			} else {
				mkeys := val.MapKeys()
				keys := make([]string, len(val.MapKeys()))
				kkmap := make(map[string]reflect.Value)

				for i, k := range mkeys {
					keys[i], _ = convertToString(k, option.tag)
					kkmap[keys[i]] = k
				}

				sort.Strings(keys)

				for _, k := range keys {
					v, _ := convertToString(val.MapIndex(kkmap[k]), option.tag)

					writeOption(writer, oname, kind, k, v, commentOption, option.iniQuote)
				}
			}
		default:
			v, _ := convertToString(val, option.tag)

			writeOption(writer, oname, kind, "", v, commentOption, option.iniQuote)
		}

		if comments {
			fmt.Fprintln(writer)
		}
	}

	if sectionwritten && !comments {
		fmt.Fprintln(writer)
	}
}

func writeOption(writer io.Writer, optionName string, optionType reflect.Kind, optionKey string, optionValue string, commentOption bool, forceQuote bool) {
	if forceQuote || (optionType == reflect.String && !isPrint(optionValue)) {
		optionValue = strconv.Quote(optionValue)
	}

	comment := ""
	if commentOption {
		comment = "; "
	}

	fmt.Fprintf(writer, "%s%s =", comment, optionName)

	if optionKey != "" {
		fmt.Fprintf(writer, " %s:%s", optionKey, optionValue)
	} else if optionValue != "" {
		fmt.Fprintf(writer, " %s", optionValue)
	}

	fmt.Fprintln(writer)
}

func writeCommandIni(command *Command, namespace string, writer io.Writer, options IniOptions) {
	command.eachGroup(func(group *Group) {
		if !group.Hidden {
			writeGroupIni(command, group, namespace, writer, options)
		}
	})

	for _, c := range command.commands {
		var nns string

		if c.Hidden {
			continue
		}

		if len(namespace) != 0 {
			nns = c.Name + "." + nns
		} else {
			nns = c.Name
		}

		writeCommandIni(c, nns, writer, options)
	}
}

func writeIni(parser *IniParser, writer io.Writer, options IniOptions) {
	writeCommandIni(parser.parser.Command, "", writer, options)
}

func writeIniToFile(parser *IniParser, filename string, options IniOptions) error {
	file, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer file.Close()

	writeIni(parser, file, options)

	return nil
}

func readIniFromFile(filename string) (*ini, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	return readIni(file, filename)
}

func readIni(contents io.Reader, filename string) (*ini, error) {
	ret := &ini{
		File:     filename,
		Sections: make(map[string]iniSection),
	}

	reader := bufio.NewReader(contents)

	// Empty global section
	section := make(iniSection, 0, 10)
	sectionname := ""

	ret.Sections[sectionname] = section

	var lineno uint

	for {
		line, err := readFullLine(reader)

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		lineno++
		line = strings.TrimSpace(line)

		// Skip empty lines and lines starting with ; (comments)
		if len(line) == 0 || line[0] == ';' || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			if line[0] != '[' || line[len(line)-1] != ']' {
				return nil, &IniError{
					Message:    "malformed section header",
					File:       filename,
					LineNumber: lineno,
				}
			}

			name := strings.TrimSpace(line[1 : len(line)-1])

			if len(name) == 0 {
				return nil, &IniError{
					Message:    "empty section name",
					File:       filename,
					LineNumber: lineno,
				}
			}

			//add random nonce to avoid collisions
			for ret.Sections[name] != nil {
				name = name + "-"
			}

			sectionname = name
			section = ret.Sections[name]

			if section == nil {
				section = make(iniSection, 0, 10)
				ret.Sections[name] = section
			}

			continue
		}

		// Parse option here
		keyval := strings.SplitN(line, "=", 2)

		if len(keyval) != 2 {
			return nil, &IniError{
				Message:    fmt.Sprintf("malformed key=value (%s)", line),
				File:       filename,
				LineNumber: lineno,
			}
		}

		name := strings.TrimSpace(keyval[0])
		value := strings.TrimSpace(keyval[1])
		quoted := false

		if len(value) != 0 && value[0] == '"' {
			if v, err := strconv.Unquote(value); err == nil {
				value = v

				quoted = true
			} else {
				return nil, &IniError{
					Message:    err.Error(),
					File:       filename,
					LineNumber: lineno,
				}
			}
		}

		section = append(section, iniValue{
			Name:       name,
			Value:      value,
			Quoted:     quoted,
			LineNumber: lineno,
		})

		ret.Sections[sectionname] = section
	}

	return ret, nil
}

func (i *IniParser) matchingGroups(name string) []*Group {
	if len(name) == 0 {
		var ret []*Group

		i.parser.eachGroup(func(g *Group) {
			ret = append(ret, g)
		})

		return ret
	}

	g := i.parser.groupByName(name)

	if g != nil {
		return []*Group{g}
	}

	return nil
}

func (i *IniParser) parse(ini *ini) ([]string, []interface{}, error) {
	p := i.parser

	var quotesLookup = make(map[*Option]bool)

	var modTypes []string
	var returnFlags []interface{}
	for name, section := range ini.Sections {
		name = removeTrailingNonce(name)

		groups := i.matchingGroups(name)

		if len(groups) == 0 {
			return nil, nil, newErrorf(ErrUnknownGroup, "could not find option group `%s'", name)
		}

		for _, inival := range section {
			var opt *Option

			for _, group := range groups {
				opt = group.optionByName(inival.Name, func(o *Option, n string) bool {
					return strings.ToLower(o.tag.Get("ini-name")) == strings.ToLower(n)
				})

				if opt != nil && len(opt.tag.Get("no-ini")) != 0 {
					opt = nil
				}

				if opt != nil {
					break
				}
			}

			if opt == nil {
				if (p.Options & IgnoreUnknown) == None {
					return nil, nil, &IniError{
						Message:    fmt.Sprintf("unknown option: %s", inival.Name),
						File:       ini.File,
						LineNumber: inival.LineNumber,
					}
				}

				continue
			}

			// ini value is ignored if override is set and
			// value was previously set from non default
			if i.ParseAsDefaults && !opt.isSetDefault {
				continue
			}

			pval := &inival.Value
			if !opt.canArgument() && len(inival.Value) == 0 {
				pval = nil
			} else {
				if opt.value.Type().Kind() == reflect.Map {
					parts := strings.SplitN(inival.Value, ":", 2)

					// only handle unquoting
					if len(parts) == 2 && parts[1][0] == '"' {
						if v, err := strconv.Unquote(parts[1]); err == nil {
							parts[1] = v

							inival.Quoted = true
						} else {
							return nil, nil, &IniError{
								Message:    err.Error(),
								File:       ini.File,
								LineNumber: inival.LineNumber,
							}
						}

						s := parts[0] + ":" + parts[1]

						pval = &s
					}
				}
			}

			if err := opt.set(pval); err != nil {
				return nil, nil, &IniError{
					Message:    err.Error(),
					File:       ini.File,
					LineNumber: inival.LineNumber,
				}
			}

			// either all INI values are quoted or only values who need quoting
			if _, ok := quotesLookup[opt]; !inival.Quoted || !ok {
				quotesLookup[opt] = inival.Quoted
			}

			opt.tag.Set("_read-ini-name", inival.Name)

		}

		if name != "" && name != "Application Options" {
			c := i.parser.Find(name)
			if cmd, ok := c.data.(ZCommander); ok {
				if err := cmd.Validate([]string{}); err != nil { //validate
					log.Fatal(err)
				}
				modTypes = append(modTypes, name)
				returnFlags = append(returnFlags, c.data)
				par, _ := c.parent.(*Command)
				c.Name = "-"                                                          //remove previous command
				par.AddCommand(name, c.ShortDescription, c.LongDescription, c.module) //recreate new group with duplicate module
			}
		}
	}

	// Set any default values.
	// TODO: Copied from ParseCommandLine in parser.go; it seems like this
	// TODO: should probably be rolled into a common section.
	p.eachOption(func(c *Command, g *Group, option *Option) {
		if option.preventDefault {
			return
		}

		option.clearDefault()
	})
	// TODO: checkRequired?

	for opt, quoted := range quotesLookup {
		opt.iniQuote = quoted
	}

	return modTypes, returnFlags, nil
}

func removeTrailingNonce(s string) string {
	var j int
	for j = len(s) - 1; j > 0; j-- {
		if s[j] != '-' {
			break
		}
	}
	return s[:j+1]
}
