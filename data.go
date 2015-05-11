package main

import "bufio"
import "os"
import "fmt"
import "log"
import "strings"
import "encoding/hex"
import "strconv"
import "bytes"
import "github.com/awalterschulze/gographviz"

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type line struct {
	addr        uint16
	optcode     []byte
	description string
}

var mem map[uint16]byte
var lines []line
var code map[uint16]*line

func findString(addr uint16) (string, bool) {
	//log.Printf("looking for string at %d [%d]\n", addr, mem[addr])
	b := make([]byte, 0)
	f := false
	m, ok := mem[addr]
	for ok && isPrint(m) {
		f = true
		b = append(b, m)
		addr++
		m, ok = mem[addr]
	}
	return string(b), f
}

func isStringStart(addr uint16) bool {
	b, _ := mem[addr-1]
	c, _ := mem[addr]
	return !isPrint(b) && isPrint(c)
}

func isPrint(b byte) bool {
	if b < 127 && b >= 32 {
		return true
	}
	return false
}

func (l *line) isNOP() bool {
	return (l.optcode[0] == 0 && l.optcode[1] == 0)
}

func (l *line) isRCALL() bool {
	return (l.optcode[0] == 0 && l.optcode[1] == 7)
}

func (l *line) isBRA() bool {
	return (l.optcode[0] == 0 && (l.optcode[1]&0xF0) == 0x30)
}

func (l *line) isBRAUnconditional() bool {
	return (l.optcode[0] == 0x00 && l.optcode[1] == 0x37 )
}

func (l *line) isCALL() bool {
	return (l.optcode[0] == 0 && l.optcode[1] == 0x02 && (l.optcode[3]&0x01) == 0)
}

func (l *line) isCALLREG() bool {
	return (l.optcode[0] == 0 && l.optcode[1] == 0x01 && l.optcode[2] == 0x00 && (l.optcode[3]&0xF0) == 0x00)
}

func (l *line) isGOTO() bool {
	return (l.optcode[0] == 0 && l.optcode[1] == 0x04)
}

func (l *line) isGOTOREG() bool {
	return (l.optcode[0] == 0x00 && l.optcode[1] == 0x01 && l.optcode[2] == 0x40 && (l.optcode[3]&0xF0) == 0x00)
}

func (l *line) isRETURN() bool {
	return (l.optcode[0] == 0x00 && l.optcode[1] == 0x06 && l.optcode[2] == 0x00 && l.optcode[3] == 0x00)
}
func (l *line) String() string {
	// print chars
	// decode intermediats
	parts := strings.Split(l.description, " ")
	for i := range parts {
		parts[i] = strings.TrimRight(parts[i], ",")
	}

	as := make([]string, 0)
	for _, part := range parts {
		if len(part) > 1 && part[0] == '#' {
			di, err := strconv.ParseInt(part[1:], 0, 32)
			check(err)

			prog_addr := uint16(di - 0x8000)
			//log.Printf("Checking addr %#x\n", prog_addr)
			s, ok := findString(prog_addr)
			if ok {
				as = append(as, s)
			}

			d := byte(di)
			if isPrint(d) {
				as = append(as, string(d))
			}
		}
	}

	if l.isRCALL() {
		addr := l.relativeJumpLoc()
		dest := fmt.Sprintf("call %s()", f(addr))
		as  = append(as, dest)
	}
	if l.isCALL() {
		addr := l.jumpLoc()
		dest := fmt.Sprintf("call %s()", f(addr))
		as  = append(as, dest)
	}


	var s string

	if len(as) > 0 {
		for _, b := range as {
			s = fmt.Sprintf("%s[%s]", s, b)
		}
	}

	s = strings.Replace(s, "\"", "\\\"", -1)
	//d := l.description
	d := strings.Replace(l.description, "\"", "\\\"", -1)

	return fmt.Sprintf("%0#4x: [%#08x] %s    %s", l.addr, l.optcode, d, s)


}
func (l *line) relativeJumpLoc() uint16 {
	high := uint16(l.optcode[2]) << 8
	low := uint16(l.optcode[3])
	offset := (high + low) << 1
	dest := l.addr + offset + 2
	return dest
}

func (l *line) jumpLoc() uint16 {
	high := uint16(l.optcode[2]) << 8
	low := uint16(l.optcode[3])
	dest := (high + low)
	return dest
}


func parseInput(filename string) {
	file, err := os.Open(filename)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		//lines = append(lines, scanner.Text())

		lineStr := scanner.Text()

		if lineStr[0:2] != "0x" {
			continue
		}
		parts := strings.SplitN(lineStr, " ", 3)
		if len(parts) < 2 {
			log.Fatal("Line missing data ", lineStr)
		}

		addr_str := strings.TrimRight(parts[0], ":")
		opt_str := parts[1]
		description := ""
		if len(parts) > 2 {
			description = strings.SplitN(parts[2], "  ", 2)[0]
		}

		addr, err := strconv.ParseInt(addr_str, 0, 32)
		check(err)

		if len(opt_str) < 3 || opt_str[0:2] != "0x" {
			log.Fatal("Unknown OPT [%s]\n", opt_str)
		}
		opt_bytes, err := hex.DecodeString(opt_str[2:])
		check(err)
		if len(opt_bytes) != 4 {
			log.Fatal("Unknown Hex OPT [%s]\n", opt_str)
		}

		var line line
		line.addr = uint16(addr)
		line.optcode = opt_bytes
		line.description = description
		lines = append(lines, line)

		code[line.addr] = &line

		mem[line.addr] = line.optcode[3]
		mem[line.addr+1] = line.optcode[2]
	}

}


func printAnnotated() {
	// print?
	for _, line := range lines {

		fmt.Print(line.String())

		// print string data
		if line.isNOP() {
			if isStringStart(line.addr + 1) {
				s, ok := findString(line.addr + 1)
				if ok {
					fmt.Printf("\t\t\t[%s]", s)
				}
			} else {
				if isStringStart(line.addr) {
					s, ok := findString(line.addr)
					if ok {
						fmt.Printf("\t\t\t[%s]", s)
					}
				}
			}
		}

		// print chars
		// decode intermediats
		parts := strings.Split(line.description, " ")
		for i := range parts {
			parts[i] = strings.TrimRight(parts[i], ",")
		}

		as := make([]string, 0)
		for _, part := range parts {
			if len(part) > 1 && part[0] == '#' {
				di, err := strconv.ParseInt(part[1:], 0, 32)
				check(err)

				prog_addr := uint16(di - 0x8000)
				//log.Printf("Checking addr %#x\n", prog_addr)
				s, ok := findString(prog_addr)
				if ok {
					as = append(as, s)
				}

				d := byte(di)
				if isPrint(d) {
					as = append(as, string(d))
				}
			}
		}

		if len(as) > 0 {
			fmt.Printf("\t\t\t\t\t")
			for _, b := range as {
				fmt.Printf("[%s]", b)
			}
		}

		fmt.Printf("\n")
	}

}

func findFunctions() []uint16 {
	// graph
	// find all functions
	functions := make([]uint16, 0, 20)
	fmap := make(map[uint16]bool)
	for _, line := range code {
		if line.isRCALL() {
			dest := line.relativeJumpLoc()
			_, ok := fmap[dest]
			if !ok {
				functions = append(functions, dest)
				fmap[dest] = true
			}
		}
	}
	
	for _, line := range code {
		if line.isCALL() {
			dest := line.jumpLoc()
			_, ok := fmap[dest]
			if !ok {
				functions = append(functions, dest)
				fmap[dest] = true
			}
		}
	}

	return functions
}

type stack []uint16
func (s stack) Empty() bool { return len(s) == 0 }
func (s stack) Peek() uint16   { return s[len(s)-1] }
func (s *stack) Put(i uint16)  { (*s) = append((*s), i) }
func (s *stack) Pop() uint16 {
	d := (*s)[len(*s)-1]
	(*s) = (*s)[:len(*s)-1]
	return d
}

type block struct {
	addr		uint16
	lines		[]*line
	branches	[]uint16
}

func NewBlock(l *line) *block {
	if l == nil {
		log.Fatal("Can not add block for out of bounds code")
	}
	var b block
	b.addr = l.addr
	b.lines = make([]*line,0,4)
	b.branches = make([]uint16,0,2)
	return &b
}

func (b *block) addLine(l *line) {
	if l != nil {
		b.lines = append(b.lines, l)
	}
}

func (b *block) addBranch(o uint16) {
	b.branches = append(b.branches, o)
}

func (b *block) fnString() string {
	return f(b.addr)
}

func (b *block) addrString() string {
	return fmt.Sprintf("\"%#4x\"", b.addr)
}

func (b *block) String() string {
	var buffer bytes.Buffer
	for _, line := range b.lines {
		buffer.WriteString(line.String())
		buffer.WriteString("\\l")
	}
	return buffer.String()
}

func (b *block) isReturned() bool {
	if len(b.lines) == 0 {
		return false
	}
	l := len(b.lines) - 1
	return b.lines[l].isRETURN()
}

func (b *block) getAttributes() map[string]string {
	m := make(map[string]string)
	m["label"] = fmt.Sprintf("\"%s\"", b.String())
	m["shape"] = "box"
	m["fontname"] = "Monospace"
	m["fontsize"] = "10"
	m["width"] = "5"
	return m
}

var blockMap map[uint16]*block

func saveGraph(g *gographviz.Graph) {
	f, err := os.Create("out/"+g.Name+".dot")
	check(err)
	defer f.Close()

	_, err = f.WriteString(g.String())
	check(err)
}


func printDotGraph(functions []uint16) {

	brAttr1 := make(map[string]string)
	//brAttr1["label"] = "T"
	brAttr1["color"] = "green"
	brAttr2 := make(map[string]string)
	brAttr2["color"] = "red"
	//brAttr2["label"] = "F"

	for _, addr := range functions {
		b := blockMap[addr]
		fn := gographviz.NewGraph()
		//fname := "\""+b.fnString()+"\""
		fname := b.fnString()
		fn.SetName(fname)
		fn.SetDir(true)
		fn.SetStrict(true)

		// DFS
		visited := make(map[uint16]bool)
		var s stack
		s.Put(addr)
		for !s.Empty() {
			a := s.Pop()
			if !visited[a] {
				visited[a] = true
				fn.AddNode(fname, blockMap[a].addrString(), blockMap[a].getAttributes())
				if len(blockMap[a].branches) == 1 {
					if blockMap[blockMap[a].branches[0]] != nil {
						fn.AddEdge(blockMap[a].addrString(), blockMap[blockMap[a].branches[0]].addrString(), true, nil)
						if !visited[blockMap[a].branches[0]] {
							s.Put(blockMap[a].branches[0])
						}
					}
				}
				if len(blockMap[a].branches) == 2 {

					if blockMap[blockMap[a].branches[1]] != nil {
						fn.AddEdge(blockMap[a].addrString(), blockMap[blockMap[a].branches[1]].addrString(), true, brAttr2)
						if !visited[blockMap[a].branches[1]] {
							s.Put(blockMap[a].branches[1])
						}
					}
					if blockMap[blockMap[a].branches[0]] != nil {
						fn.AddEdge(blockMap[a].addrString(), blockMap[blockMap[a].branches[0]].addrString(), true, brAttr1)
						if !visited[blockMap[a].branches[0]] {
							s.Put(blockMap[a].branches[0])
						}

					}
				}
			}
		}

		saveGraph(fn)
	}

}

func f(a uint16) string {
	name, ok := func_names[a]
	if ok {
	return fmt.Sprintf("sub_%s", name)
	}
	return fmt.Sprintf("sub_%04x", a)
}

func printFunctionGraph(fgraph map[uint16]map[uint16]bool) {

	fn := gographviz.NewGraph()
	fname := "Functions"
	fn.SetName(fname)
	fn.SetDir(true)
	fn.SetStrict(true)

	for fnaddr := range fgraph {
		fn.AddNode(fname, f(fnaddr), nil) //TODO
		for calledfn := range fgraph[fnaddr] {
			fn.AddEdge(f(fnaddr), f(calledfn), true, nil)
		}

	}

	saveGraph(fn)

}


var fnGraph map[uint16]map[uint16]bool

// build graph
func buildGraph(functions []uint16) {
	log.Printf("creating graph of %d functions", len(functions))

	blockMap = make(map[uint16]*block)
	fnGraph = make(map[uint16]map[uint16]bool)

	for _, addr := range functions {
		fnGraph[addr] = make(map[uint16]bool)
		var s stack
		s.Put(addr)
		// find all block starting locations
		bStart := make(map[uint16]bool)
		visited := make(map[uint16]bool)
		for !s.Empty() {
			f := s.Pop()
			visited[f] = true
			_, ok := code[f]
			if !ok {
				log.Printf("jump to missing loc %04x from fucntion starting on %04x", f, addr)
				continue
			}
			for !code[f].isRETURN() {
				line := code[f]
				if line.isBRA() {
					dest := line.relativeJumpLoc()
					bStart[dest] = true
					_, ok := visited[dest]
					if !ok {
						s.Put(dest)
					}
					if !line.isBRAUnconditional() {
						bStart[f+2] = true
						_, ok := visited[f+2]
						if !ok {
							s.Put(f+2)
						}
					}
					break
				}
				if line.isGOTO() {
					dest := line.jumpLoc()
					bStart[dest] = true
					_, ok := visited[dest]
					if !ok {
						s.Put(dest)
					}
					break
				}
				if line.isGOTOREG() {
					break
				}
				if line.isCALL() {
					dest := line.jumpLoc()
					fnGraph[addr][dest] = true
				}
				if line.isRCALL() {
					dest := line.relativeJumpLoc()
					fnGraph[addr][dest] = true
				}
				f = f + 2
			}
		}

		if !s.Empty() {
			log.Fatal("exiting with non-empty block stack")
		}



		//var s stack
		// create graph
		//printed := make(map[uint16]bool)
		s.Put(addr)
		for !s.Empty() {
			f := s.Pop()
			if code[f] == nil {
				continue
			}
			b := NewBlock(code[f])
			blockMap[f] = b
			for !code[f].isRETURN() {
				line := code[f]
				b.addLine(line)
				if line.isBRA() {
					dest := line.relativeJumpLoc()
					b.addBranch(dest)
					_, ok := blockMap[dest]
					if !ok {
						s.Put(dest)
					}
					if !line.isBRAUnconditional() {
						b.addBranch(f+2)
						_, ok := blockMap[f+2]
						if !ok {
							s.Put(f+2)
						}
					}
					break
				}
				if line.isGOTO() {
					dest := line.jumpLoc()
					b.addBranch(dest)
					_, ok := blockMap[dest]
					if !ok {
						s.Put(dest)
					}
					break
				}
				if line.isGOTOREG() {
					break
				}
				// check for insert joins from branches
				if bStart[f+2] {
					b.addBranch(f+2)
					_, ok := blockMap[f+2]
					if !ok {
						s.Put(f+2)
					}
					break
				}
				f = f + 2
			}
			if code[f].isRETURN() && !b.isReturned() {
				b.addLine(code[f])
			}
		}
	}

	log.Printf("created %d blocks", len(blockMap))

}



func main() {
	if len(os.Args) != 2 {
		fmt.Println("Pass asm file to parse")
		return
	}

	mem = make(map[uint16]byte)
	lines = make([]line, 0, 100)
	code = make(map[uint16]*line)
	func_names = make(map[uint16]string)

	parseInput(os.Args[1])

	parseIntVector()
	parseAliases()

	functions := findFunctions()

	for loc := range func_names {
		// NOTE may add duplicates
		functions = append(functions, loc)
	}

	buildGraph(functions)

	printDotGraph(functions)

	printFunctionGraph(fnGraph)
	
	//printAnnotated()
}

var func_names map[uint16]string

func parseAliases () {
	file, err := os.Open("aliases.csv")
	check(err)
	defer file.Close()


	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			log.Fatal("could not parts aliases line ", line)
		}
		addr_str := parts[0]
		name := parts[1]

		addr64, err := strconv.ParseInt(addr_str, 0, 16)
		check(err)
		addr := uint16(addr64)

		func_names[addr] = name

		log.Printf("Naming function %03x [%s]", addr, name)
	}
}


func parseIntVector () {
	file, err := os.Open("int_vector.csv")
	check(err)
	defer file.Close()


	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			log.Fatal("could not parts int-vector line ", line)
		}
		addr_str := parts[0]
		name := parts[1]

		addr64, err := strconv.ParseInt(addr_str, 0, 16)
		check(err)
		addr := uint16(addr64)

		// derefence pointers
		b1 := mem[addr]
		b2 := mem[addr+1]

		loc := (uint16(b2) << 8) | uint16(b1)

		func_names[loc] = name


		log.Printf("Adding function %04x [%s]", loc, name)
	}
}

